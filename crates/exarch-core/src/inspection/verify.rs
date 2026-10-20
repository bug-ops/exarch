//! Archive verification implementation.

use std::path::Path;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::inspection::list::list_archive;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::ManifestEntryKind;
use crate::inspection::manifest::ManifestEntryType;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::VerificationIssue;
use crate::inspection::report::VerificationReport;
use crate::security::fs_view::FsView;
use crate::security::fs_view::Node;
use crate::security::fs_view::VirtualTree;
use crate::security::fs_view::check_name_lengths;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::QuotaTracker;
use crate::security::zipbomb::validate_entry_compression;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// Verifies an already-listed manifest against the security config.
///
/// Used by `ArchiveFormat::verify()` to avoid re-opening the archive.
/// Performs the same checks as `verify_archive` but starts from a manifest
/// produced by `ArchiveFormat::list()`.
///
/// Entries are validated against an in-memory [`VirtualTree`] of what
/// extraction would create, so nothing is written to disk. Hardlinks are
/// materialized after every other entry, so their path and target are
/// validated against the final tree.
pub(crate) fn verify_manifest(
    manifest: &ArchiveManifest,
    config: &SecurityConfig<Validated>,
) -> Result<VerificationReport> {
    let temp_dir = tempfile::TempDir::new()?;
    let temp_dest = DestDir::new(temp_dir.path())?;

    let mut tree = VirtualTree::new(temp_dest.as_path());
    let mut quota_tracker = QuotaTracker::new();
    let mut hardlink_tracker = HardlinkTracker::new();

    let mut lists = Vec::with_capacity(manifest.entries().len());
    let mut deferred = Vec::new();
    for (index, entry) in manifest.entries().iter().enumerate() {
        let outcome = verify_entry(
            entry,
            config,
            &temp_dest,
            &mut tree,
            &mut quota_tracker,
            &mut hardlink_tracker,
        );
        if outcome.hardlink_pending {
            deferred.push(index);
        }
        let mut issues = outcome.issues;
        issues.extend(check_heuristics(entry));
        lists.push(issues);
    }

    for index in deferred {
        let entry = &manifest.entries()[index];
        if let Err(e) =
            verify_deferred_hardlink(entry, config, &temp_dest, &mut tree, &mut hardlink_tracker)
        {
            lists[index].push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
        }
    }

    Ok(VerificationReport::from_entry_issue_lists(manifest, lists))
}

/// Verifies archive security without extracting.
///
/// Performs metadata-only validation:
/// - Security checks (path traversal, zip bombs, CVEs)
/// - Policy checks (file types, permissions)
///
/// Payload integrity (checksums, decode-to-end) is not verified: the report's
/// `integrity_status` is [`CheckStatus::Skipped`](crate::CheckStatus::Skipped).
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
/// - Declared compressed sizes exceed the archive length
/// - An entry name is a path traversal (`..` component, or an absolute path
///   unless `allowed.absolute_paths` is set): the listing step rejects it with
///   [`ArchiveError::PathTraversal`] before a report exists
///
/// Other security violations are reported in `VerificationReport::issues`
/// instead: disallowed links, link targets that escape the destination,
/// hardlinks whose target never appears, quota and compression-ratio
/// violations, NUL bytes, banned components and unsafe permissions.
///
/// # Limitations
///
/// Verification models only the archive's own entries; it cannot account for
/// files, directories or links already present in the extraction destination,
/// so a PASS does not guarantee that extraction into a non-empty destination
/// succeeds. Symlink chains are cut off after 40 hops, which may differ from
/// the host's own limit. On macOS and Windows hosts entry names are matched
/// after lowercasing only: names the host filesystem treats as equal under
/// Unicode normalisation (NFC/NFD) or special case folding (final sigma) are
/// not modelled. Windows component checks (reserved names, `:`, trailing dot
/// or space) run only on Windows hosts.
///
/// Verification models extraction that skips an existing entry. With
/// overwrite semantics extraction keeps the last entry at a path, which
/// verification cannot model.
///
/// Hardlinks are materialized after every other entry, so their path and
/// target are validated against the final tree.
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
/// if report.status() == VerificationStatus::Pass {
///     println!("Archive is safe to extract");
/// } else {
///     eprintln!("Security issues found:");
///     for issue in report.issues() {
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
/// entry via `SafePath`/`SafeSymlink` validation), not abort the listing step
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

struct EntryOutcome {
    issues: Vec<VerificationIssue>,
    /// A hardlink that passed phase-one validation and awaits phase two.
    hardlink_pending: bool,
}

fn verify_entry(
    entry: &ArchiveEntry,
    config: &SecurityConfig<Validated>,
    dest: &DestDir,
    tree: &mut VirtualTree,
    quota_tracker: &mut QuotaTracker,
    hardlink_tracker: &mut HardlinkTracker,
) -> EntryOutcome {
    let mut issues = Vec::new();
    let mut hardlink_pending = false;

    // Path validation — result cached to avoid repeated syscalls for
    // symlink/hardlink checks
    let path_result = check_name_lengths(&entry.path)
        .map_err(ArchiveError::Io)
        .and_then(|()| SafePath::validate_in(&entry.path, dest, config, tree));
    if let Err(ref e) = path_result {
        issues.push(VerificationIssue::from_error(e, Some(entry.path.clone())));
    }

    // Quota validation using reserve (combines all checks)
    if let Err(e) = quota_tracker.reserve(entry.size, config) {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Compression ratio validation (zip bomb detection)
    if let Err(e) = validate_entry_compression(&entry.compression, entry.size, config) {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    if let Ok(ref safe_path) = path_result {
        let link_result = match &entry.kind {
            ManifestEntryKind::Symlink { target } => Some(
                target
                    .as_deref()
                    .ok_or_else(|| missing_link_target(ManifestEntryType::Symlink))
                    .and_then(|t| {
                        check_target_lengths(t)?;
                        SafeSymlink::validate_in(safe_path, t, dest, config, tree).map(drop)
                    }),
            ),
            ManifestEntryKind::Hardlink { target } => Some(
                target
                    .as_deref()
                    .ok_or_else(|| missing_link_target(ManifestEntryType::Hardlink))
                    .and_then(|t| {
                        check_target_lengths(t)?;
                        hardlink_tracker.validate_hardlink_in(safe_path, t, dest, config, tree)
                    }),
            ),
            ManifestEntryKind::File | ManifestEntryKind::Directory => None,
        };
        match link_result {
            Some(Err(e)) => {
                issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
            }
            Some(Ok(())) if matches!(entry.kind, ManifestEntryKind::Hardlink { .. }) => {
                hardlink_pending = true;
            }
            _ => {
                if let Err(e) = record_entry(tree, safe_path.as_path(), &entry.kind) {
                    issues.push(VerificationIssue::from_error(
                        &ArchiveError::Io(e),
                        Some(entry.path.clone()),
                    ));
                }
            }
        }
    }

    // Permission validation
    if let Some(mode) = entry.mode
        && let Err(e) = check_permissions(&entry.path, mode, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    EntryOutcome {
        issues,
        hardlink_pending,
    }
}

fn check_target_lengths(target: &Path) -> Result<()> {
    check_name_lengths(target).map_err(ArchiveError::Io)
}

/// Records a successfully validated non-hardlink entry in the tree.
fn record_entry(
    tree: &mut VirtualTree,
    path: &Path,
    kind: &ManifestEntryKind,
) -> std::io::Result<()> {
    let node = match kind {
        ManifestEntryKind::File => Node::File,
        ManifestEntryKind::Directory => Node::Dir,
        ManifestEntryKind::Symlink { target: Some(t) } => Node::Symlink(t.clone()),
        ManifestEntryKind::Symlink { target: None } | ManifestEntryKind::Hardlink { .. } => {
            return Ok(());
        }
    };
    tree.insert(path, node)
}

/// Phase two for a hardlink: re-validates its link path and target against the
/// final tree, requires the target to exist, then materializes the link.
fn verify_deferred_hardlink(
    entry: &ArchiveEntry,
    config: &SecurityConfig<Validated>,
    dest: &DestDir,
    tree: &mut VirtualTree,
    hardlink_tracker: &mut HardlinkTracker,
) -> Result<()> {
    let ManifestEntryKind::Hardlink {
        target: Some(target),
    } = &entry.kind
    else {
        return Ok(());
    };
    let link_path = SafePath::validate_in(&entry.path, dest, config, tree)?;
    hardlink_tracker.validate_hardlink_in(&link_path, target, dest, config, tree)?;
    let target_full = dest.as_path().join(target);
    if !tree.exists(&target_full) {
        return Err(hardlink_target_missing(target));
    }
    if tree.resolves_to_dir(&target_full) {
        return Err(ArchiveError::InvalidArchive(format!(
            "hardlink target is a directory: {}",
            target.display()
        )));
    }
    tree.insert(link_path.as_path(), Node::File)?;
    Ok(())
}

fn missing_link_target(kind: ManifestEntryType) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!("{} target is missing", kind.as_str().to_ascii_lowercase()),
    }
}

fn check_permissions(path: &Path, mode: u32, config: &SecurityConfig<Validated>) -> Result<()> {
    let sanitized = sanitize_permissions(mode, config);
    (sanitized.as_u32() == mode).ok_or_else(|| ArchiveError::InvalidPermissions {
        path: path.to_path_buf(),
        mode,
    })
}

fn check_heuristics(entry: &ArchiveEntry) -> Vec<VerificationIssue> {
    let mut issues = Vec::new();

    // Executable file detection
    if let Some(mode) = entry.mode
        && mode & 0o111 != 0
        && entry.kind == ManifestEntryKind::File
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

const SUSPICIOUS_EXTENSIONS: [&str; 5] = ["exe", "dll", "sh", "bat", "cmd"];

fn is_suspicious_extension(path: &Path) -> bool {
    path.extension().is_some_and(|ext| {
        SUSPICIOUS_EXTENSIONS
            .iter()
            .any(|s| ext.eq_ignore_ascii_case(s))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::inspection::manifest::EntryCompression;
    use crate::inspection::report::VerificationStatus;
    use crate::test_utils::tar_with_pax_nul_path;
    use std::assert_matches;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn manifest_of(entries: Vec<(&str, ManifestEntryKind)>) -> ArchiveManifest {
        let mut manifest = ArchiveManifest::new(crate::formats::detect::ArchiveType::Tar);
        for (path, kind) in entries {
            manifest
                .add_entry(ArchiveEntry::new(PathBuf::from(path), kind, 0))
                .unwrap();
        }
        manifest
    }

    fn link_config() -> SecurityConfig<Validated> {
        SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true)
            .validate()
            .unwrap()
    }

    fn symlink_to(target: &str) -> ManifestEntryKind {
        ManifestEntryKind::Symlink {
            target: Some(PathBuf::from(target)),
        }
    }

    fn hardlink_to(target: &str) -> ManifestEntryKind {
        ManifestEntryKind::Hardlink {
            target: Some(PathBuf::from(target)),
        }
    }

    #[test]
    fn overlong_link_targets_are_reported_without_resolution() {
        let long = "a".repeat(1 << 20);
        let manifest = manifest_of(vec![
            ("s", symlink_to(&long)),
            ("t", ManifestEntryKind::File),
            ("h", hardlink_to(&long)),
        ]);
        let report = verify_manifest(&manifest, &link_config()).unwrap();
        let too_long = report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::InvalidArchive)
            .count();
        assert_eq!(too_long, 2, "{:?}", report.issues());
    }

    #[test]
    fn phase_two_resolves_link_path_through_tree() {
        let manifest = manifest_of(vec![
            ("real", ManifestEntryKind::Directory),
            ("alias", symlink_to("real")),
            ("real/t", ManifestEntryKind::File),
            ("alias/h", hardlink_to("real/t")),
            ("again", hardlink_to("real/h")),
        ]);
        let report = verify_manifest(&manifest, &link_config()).unwrap();
        assert!(report.issues().is_empty(), "{:?}", report.issues());
    }

    #[test]
    fn phase_two_reports_absent_hardlink_target() {
        let manifest = manifest_of(vec![("h", hardlink_to("missing"))]);
        let report = verify_manifest(&manifest, &link_config()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(report.issues().iter().any(|i| {
            i.category == IssueCategory::InvalidArchive
                && i.message.contains("hardlink target does not exist")
        }));
    }

    #[test]
    fn phase_two_accepts_target_declared_later() {
        let manifest = manifest_of(vec![
            ("h", hardlink_to("later")),
            ("later", ManifestEntryKind::File),
        ]);
        let report = verify_manifest(&manifest, &link_config()).unwrap();
        assert!(report.issues().is_empty(), "{:?}", report.issues());
    }

    #[test]
    fn phase_one_failure_is_not_reported_again_in_phase_two() {
        let manifest = manifest_of(vec![
            ("t", ManifestEntryKind::File),
            ("h", hardlink_to("../outside")),
        ]);
        let report = verify_manifest(&manifest, &link_config()).unwrap();
        let escapes = report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::HardlinkEscape)
            .count();
        assert_eq!(escapes, 1);
    }

    #[test]
    fn test_is_suspicious_extension() {
        assert!(is_suspicious_extension(Path::new("file.exe")));
        assert!(is_suspicious_extension(Path::new("file.dll")));
        assert!(is_suspicious_extension(Path::new("file.sh")));
        assert!(is_suspicious_extension(Path::new("file.bat")));
        assert!(is_suspicious_extension(Path::new("FILE.EXE")));
        assert!(is_suspicious_extension(Path::new("run.Bat")));
        assert!(is_suspicious_extension(Path::new("x.CMD")));
        assert!(!is_suspicious_extension(Path::new("file.txt")));
        assert!(!is_suspicious_extension(Path::new("file.rs")));
    }

    #[test]
    fn test_check_heuristics_executable() {
        let entry = crate::inspection::manifest::ArchiveEntry {
            path: PathBuf::from("test.sh"),
            kind: ManifestEntryKind::File,
            size: 100,
            compression: EntryCompression::Unknown,
            mode: Some(0o755),
            modified: None,
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
            kind: ManifestEntryKind::File,
            size: 100,
            compression: EntryCompression::Unknown,
            mode: Some(0o644),
            modified: None,
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
            kind: ManifestEntryKind::File,
            size: 100,
            compression: EntryCompression::Unknown,
            mode: Some(0o644),
            modified: None,
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
            kind: ManifestEntryKind::File,
            size: 100,
            compression: EntryCompression::Unknown,
            mode: Some(0o644),
            modified: None,
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
            report.status(),
            VerificationStatus::Pass,
            "Safe archive should pass verification"
        );
        assert_eq!(report.total_entries(), 1);
        assert_eq!(report.suspicious_entries(), 0);
        assert!(
            report.issues().is_empty(),
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
            report.status(),
            VerificationStatus::Fail,
            "oversized entry must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries(), 1);
        assert!(
            report.issues().iter().any(|i| {
                i.severity == IssueSeverity::High
                    && i.category == IssueCategory::QuotaExceeded
                    && i.message.contains("single file size")
            }),
            "expected a High-severity QuotaExceeded FileSize issue, got: {:?}",
            report.issues()
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
    // identified as a real regression: verify_entry's own path validation
    // already had a working graceful NUL-byte check via SafePath, and the
    // list-level check was aborting before that mechanism ever ran.
    // `listing_config_for_verify` now also relaxes the list-level NUL-byte
    // check (see `SecurityConfig::relaxed_for_verify_preflight`), restoring
    // the original graceful-report behavior — this test was rewritten (not
    // just renamed) to assert that restored behavior instead of the
    // hard-error behavior it previously pinned.
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
            report.status(),
            VerificationStatus::Fail,
            "NUL-byte entry path must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries(), 1);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.message.contains("null bytes")),
            "expected an issue mentioning null bytes, got: {:?}",
            report.issues()
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
            report.status(),
            VerificationStatus::Warning,
            "non-UTF8 entry name must surface as a Warning, not silently Pass"
        );
        assert_eq!(
            report.suspicious_entries(),
            1,
            "a Medium+ heuristic issue must be reflected in suspicious_entries, \
             or the report is self-contradictory (Warning with 0 suspicious entries)"
        );
        assert!(
            report.issues().iter().any(|i| {
                i.category == IssueCategory::SuspiciousPath && i.message.contains("not valid UTF-8")
            }),
            "expected a SuspiciousPath issue mentioning UTF-8, got: {:?}",
            report.issues()
        );
    }

    // Regression test for #430 follow-up (round 3, item 2): a hardlink entry
    // with no link target at all must still surface as a graceful
    // VerificationIssue from verify_archive, not the InvalidArchive hard
    // error that bare `list_archive` now raises (see
    // `test_list_tar_hardlink_missing_target_rejected` in
    // `inspection::list::tests`). `relaxed_for_verify_preflight` lets the
    // missing target through the pre-flight listing pass as `None`;
    // `verify_entry` reports it as a SecurityPolicy issue.
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

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let report = verify_archive(temp_file.path(), &config)
            .expect("verify_archive must report a missing hardlink target, not error out");

        assert_eq!(
            report.status(),
            VerificationStatus::Fail,
            "missing hardlink target must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries(), 1);
        assert!(
            report.issues().iter().any(|i| {
                i.category == IssueCategory::SecurityPolicy
                    && i.message.contains("hardlink target is missing")
            }),
            "expected a SecurityPolicy issue citing the missing target, got: {:?}",
            report.issues()
        );
    }

    fn link_tar(
        entry_type: tar::EntryType,
        names_and_targets: &[(&str, Option<&str>)],
    ) -> NamedTempFile {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for (name, target) in names_and_targets {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(0);
            header.set_entry_type(entry_type);
            if let Some(target) = target {
                header.set_link_name(target).unwrap();
            }
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
        }
        temp_file.write_all(&builder.into_inner().unwrap()).unwrap();
        temp_file.flush().unwrap();
        temp_file
    }

    fn hardlink_config(allowed: bool) -> SecurityConfig {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = allowed;
        config
    }

    #[test]
    fn test_verify_hardlink_rejected_when_not_allowed() {
        let archive = link_tar(tar::EntryType::Link, &[("link", Some("target.txt"))]);
        let report = verify_archive(archive.path(), &hardlink_config(false)).unwrap();

        assert_eq!(report.status(), VerificationStatus::Fail);
        assert_eq!(report.security_status(), crate::CheckStatus::Fail);
        assert!(report.issues().iter().any(|i| {
            i.category == IssueCategory::SecurityPolicy
                && i.message.contains("hardlinks not allowed")
        }));
    }

    #[test]
    fn test_verify_hardlink_inside_dest_passes_when_allowed() {
        let archive = link_tar(tar::EntryType::Link, &[("link", Some("target.txt"))]);
        let report = verify_archive(archive.path(), &hardlink_config(true)).unwrap();

        assert!(
            !report.issues().iter().any(|i| i.category.is_security()),
            "got: {:?}",
            report.issues()
        );
    }

    #[test]
    fn test_verify_hardlink_duplicate_target_passes_when_allowed() {
        let archive = link_tar(
            tar::EntryType::Link,
            &[("a", Some("target.txt")), ("b", Some("target.txt"))],
        );
        let report = verify_archive(archive.path(), &hardlink_config(true)).unwrap();

        assert!(!report.issues().iter().any(|i| i.category.is_security()));
    }

    #[test]
    fn test_verify_hardlink_target_escaping_dest_flagged() {
        let archive = link_tar(tar::EntryType::Link, &[("link", Some("../outside.txt"))]);
        let report = verify_archive(archive.path(), &hardlink_config(true)).unwrap();

        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::HardlinkEscape),
            "got: {:?}",
            report.issues()
        );
    }

    #[test]
    fn test_verify_hardlink_absolute_target_flagged() {
        let archive = link_tar(tar::EntryType::Link, &[("link", Some("/etc/passwd"))]);
        let report = verify_archive(archive.path(), &hardlink_config(true)).unwrap();

        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::HardlinkEscape),
            "got: {:?}",
            report.issues()
        );
    }

    #[test]
    fn test_verify_symlink_missing_target_reports_policy_issue() {
        for allowed in [false, true] {
            let archive = link_tar(tar::EntryType::Symlink, &[("link", None)]);
            let mut config = SecurityConfig::default();
            config.allowed.symlinks = allowed;
            let report = verify_archive(archive.path(), &config).unwrap();

            assert_eq!(report.status(), VerificationStatus::Fail);
            assert!(
                report.issues().iter().any(|i| {
                    i.category == IssueCategory::SecurityPolicy
                        && i.message.contains("symlink target is missing")
                }),
                "allowed={allowed}, got: {:?}",
                report.issues()
            );
        }
    }

    // Note: Full CVE regression tests for path traversal require real malicious
    // archives that cannot be created using the tar crate (it validates paths).
    // Those tests should be added in crates/exarch-core/tests/security/ with
    // pre-built malicious fixtures. This test verifies the workflow works with
    // archives that tar crate accepts.

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

        // Default config blocks ALL symlinks, so check that the issue is
        // detected
        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config).unwrap();

        assert_eq!(
            report.status(),
            VerificationStatus::Fail,
            "Symlink should fail verification with default config"
        );
        assert_eq!(report.total_entries(), 1);
        assert_eq!(report.suspicious_entries(), 1);
        assert!(!report.issues().is_empty(), "Should detect symlink");

        let has_symlink_issue = report.issues().iter().any(|i| {
            matches!(i.category, IssueCategory::SecurityPolicy) && i.message.contains("symlink")
        });

        assert!(
            has_symlink_issue,
            "Should have symlink-related issue, got: {:?}",
            report.issues()
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
            !report.issues().is_empty(),
            "Should detect setuid permission issue"
        );
        assert!(
            report
                .issues()
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

        assert!(!report.issues().is_empty(), "Should detect executable file");
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::ExecutableFile),
            "Should have ExecutableFile issue"
        );
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::SuspiciousPath),
            "Should have SuspiciousPath issue for .sh extension"
        );
        assert_eq!(
            report.suspicious_entries(),
            0,
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
