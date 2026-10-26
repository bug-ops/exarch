//! Archive verification implementation.

use std::path::Path;

use crate::ArchiveError;
use crate::IntegrityCheck;
use crate::Result;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::config::Validated;
use crate::formats::SevenZArchive;
use crate::formats::ZipArchive;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::detect_format;
use crate::formats::traits::ArchiveFormat;
use crate::inspection::integrity::IntegrityOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::list::ListPass;
use crate::inspection::list::list_detected;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::LinkTarget;
use crate::inspection::manifest::ManifestEntryKind;
use crate::inspection::manifest::ManifestEntryType;
use crate::inspection::manifest::OversizedEntry;
use crate::inspection::report::ArchiveStructure;
use crate::inspection::report::IntegrityScope;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::VerificationIssue;
use crate::inspection::report::VerificationReport;
use crate::security::fs_view::CollisionKind;
use crate::security::fs_view::FsView;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::NameCollision;
use crate::security::fs_view::Node;
use crate::security::fs_view::VirtualTree;
use crate::security::fs_view::check_link_target_length;
use crate::security::fs_view::check_name_lengths;
use crate::security::fs_view::name_too_long;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::QuotaTracker;
use crate::security::zipbomb::validate_entry_compression;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_symlink::require_symlinks_allowed;

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
    integrity: Option<IntegrityOutcome>,
) -> Result<VerificationReport> {
    verify_manifest_with_structure(
        manifest,
        config,
        &ArchiveStructure::of_manifest(manifest),
        integrity,
    )
}

/// Like [`verify_manifest`], for a format that also reports structural
/// findings and a record count of its own.
pub(crate) fn verify_manifest_with_structure(
    manifest: &ArchiveManifest,
    config: &SecurityConfig<Validated>,
    structure: &ArchiveStructure<'_>,
    integrity: Option<IntegrityOutcome>,
) -> Result<VerificationReport> {
    verify_with_tree(manifest, config, structure, integrity, VirtualTree::new)
}

/// Verifies against a tree built by `make_tree`, which lets tests choose how
/// names are folded instead of taking the host's rule.
fn verify_with_tree(
    manifest: &ArchiveManifest,
    config: &SecurityConfig<Validated>,
    structure: &ArchiveStructure<'_>,
    integrity: Option<IntegrityOutcome>,
    make_tree: impl FnOnce(&Path) -> VirtualTree,
) -> Result<VerificationReport> {
    let temp_dir = tempfile::TempDir::new()?;
    let temp_dest = DestDir::new(temp_dir.path())?;

    let mut tree = make_tree(temp_dest.as_path());
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
        let materialized =
            verify_deferred_hardlink(entry, config, &temp_dest, &mut tree, &mut hardlink_tracker);
        lists[index].extend(collision_issues(&mut tree));
        if let Err(e) = materialized {
            lists[index].push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
        }
    }

    let mut archive_issues = structure.refusals().to_vec();
    archive_issues.extend(oversized_entry_issues(manifest.oversized_entries()));
    archive_issues.extend(unread_targets_issue(manifest, config));
    let scope = match integrity {
        Some(outcome) => {
            debug_assert_eq!(outcome.entry_issues.len(), lists.len());
            for (list, extra) in lists.iter_mut().zip(outcome.entry_issues) {
                list.extend(extra);
            }
            archive_issues.extend(outcome.archive_issues);
            IntegrityScope::Requested(outcome.gaps)
        }
        None => IntegrityScope::NotRequested,
    };

    lists.extend(
        tree.take_empty_merges()
            .into_iter()
            .map(|collision| vec![collision_issue(collision)]),
    );

    Ok(VerificationReport::from_entry_issue_lists(
        manifest,
        lists,
        archive_issues,
        structure,
        scope,
    ))
}

/// A manifest listed for verification, with the integrity pass outcome when
/// one was requested.
pub(crate) struct ListedForVerify {
    pub(crate) manifest: ArchiveManifest,
    pub(crate) integrity: Option<IntegrityOutcome>,
}

/// Runs `list` as the verify pre-flight, decoding payloads when `options`
/// asks for it.
///
/// `list` is the only format-specific part of verification, so
/// `verify_archive` and every `ArchiveFormat::verify` share the rest.
pub(crate) fn list_for_verify<F>(
    config: &SecurityConfig<Validated>,
    options: VerificationOptions,
    list: F,
) -> Result<ListedForVerify>
where
    F: FnOnce(&mut ListPass<'_, '_>) -> Result<ArchiveManifest>,
{
    match options.integrity {
        IntegrityCheck::Skip => Ok(ListedForVerify {
            manifest: list(&mut ListPass::VerifyPreflight(None))?,
            integrity: None,
        }),
        IntegrityCheck::DecodeToEof(budget) => {
            let mut pass = IntegrityPass::new(config, budget);
            let manifest = list(&mut ListPass::VerifyPreflight(Some(&mut pass)))?;
            Ok(ListedForVerify {
                manifest,
                integrity: Some(pass.finish()),
            })
        }
    }
}

/// Lists with `list` and verifies the manifest, for formats whose manifest is
/// their whole content.
pub(crate) fn verify_with<F>(
    config: &SecurityConfig<Validated>,
    options: VerificationOptions,
    list: F,
) -> Result<VerificationReport>
where
    F: FnOnce(&mut ListPass<'_, '_>) -> Result<ArchiveManifest>,
{
    let listed = list_for_verify(config, options, list)?;
    verify_manifest(&listed.manifest, config, listed.integrity)
}

/// Verifies archive security without extracting.
///
/// Performs metadata-only validation:
/// - Security checks (path traversal, zip bombs, CVEs)
/// - Policy checks (file types, permissions)
///
/// Payload integrity (checksums, decode-to-end) is not verified: the report's
/// `integrity_status` is
/// [`IntegrityStatus::Skipped`](crate::IntegrityStatus::Skipped).
/// Use [`verify_archive_with_options`] to request it.
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
/// - A ZIP central directory holds more records than `max_file_count`, counting
///   records the `zip` crate collapses or the end record does not count
/// - An entry name is a path traversal (`..` component, or an absolute path
///   unless `allowed.absolute_paths` is set): the listing step rejects it with
///   [`ArchiveError::PathTraversal`] before a report exists
///
/// The targets of 7z symlinks are stored in compressed entry data, so they are
/// validated only when an integrity check decodes the archive. Without one,
/// each such target stays unread and the report carries a single Medium issue
/// counting them (status at least `WARNING`); entries that would land beneath
/// an unread link are still reported. With an integrity check whose budget
/// cannot cover a link, the target stays unread in the same way.
///
/// Other security violations are reported in `VerificationReport::issues`
/// instead: disallowed links, link targets that escape the destination,
/// hardlinks whose target never appears, quota and compression-ratio
/// violations, NUL bytes, banned components, unsafe permissions and, for ZIP
/// under `zip_consistency = Enforce`, headers that disagree with the central
/// directory, duplicate names, overlapping entries and hidden records or
/// headers. The report's total is the ZIP's raw central directory count.
///
/// # Limitations
///
/// Verification models only the archive's own entries; it cannot account for
/// files, directories or links already present in the extraction destination,
/// so a PASS does not guarantee that extraction into a non-empty destination
/// succeeds. Symlink chains are cut off after a per-OS number of hops that
/// matches `std::fs::canonicalize` on macOS (33), glibc (40) and musl (39)
/// hosts; Windows (63) is unverified and other Unix hosts assume 32, where a
/// low guess can only give a false FAIL.
///
/// On macOS entry names are compared after NFD and a per-character case fold,
/// on Windows after the same fold without normalisation, and elsewhere
/// exactly. Two names that differ exactly but compare equal under that fold
/// are reported as a [`IssueCategory::NameCollision`] (High when the kinds
/// differ or a symlink is involved, Medium for two files or for directories
/// that hold entries, Low for two directories that hold none), so a merge is
/// never silent. The fold approximates the host
/// table, so a pair it merges that the host keeps apart is reported too.
/// Windows component checks (reserved names, `:`, trailing dot or space) run
/// only on Windows hosts.
///
/// Verification models extraction that skips an existing entry. With
/// overwrite semantics extraction keeps the last entry at a path, which
/// verification cannot model. A symlink entry over a path an earlier entry
/// created as a file is reported, since the two semantics diverge there.
///
/// Hardlinks are materialized after every other entry, so their path and
/// target are validated against the final tree.
///
/// # Limitations
///
/// Name lengths are checked on the entry's relative path. Extraction adds the
/// destination prefix, so a long destination can make extraction fail with
/// `File name too long` for an entry `verify` accepted.
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
    verify_archive_with_options(archive_path, config, &VerificationOptions::default())
}

/// Verifies archive security, optionally checking payload integrity.
///
/// With [`IntegrityCheck::Skip`] this is [`verify_archive`]. With
/// [`IntegrityCheck::DecodeToEof`] the payload is decoded to the decoder's EOF
/// during listing, so codec framing and checksums are verified, and
/// `integrity_status` becomes `OK`, `FAILED` or `INCOMPLETE`.
///
/// # What a status means
///
/// | Format | Verified |
/// |---|---|
/// | ZIP | per-entry CRC-32 and exact declared size; entries are independent, so a corrupt entry does not stop the scan |
/// | TAR | header checksums and that every declared data byte is present; no payload checksum |
/// | tar.gz, tar.bz2, tar.xz, tar.zst | the above plus the codec's own framing and checksums (zstd only if the frame carries one) |
/// | 7z | per-entry CRC-32 where the archive stores one, else the block CRC |
///
/// `OK` means every payload byte was decoded and every checksum the format has
/// matched. Formats without payload checksums (plain TAR, 7z entries without
/// CRC, zstd frames without a content checksum) report the weaker guarantee
/// that the data was complete and decodable. "Decode to EOF" means the
/// decoder's EOF: every gzip member, bzip2 stream and xz stream is decoded, and
/// a non-zero tail after the last one is an error.
///
/// `INCOMPLETE` means part of the payload was not verified (decompression
/// budget, a resource limit, a solid 7z archive while `allow_solid_archives`
/// is off, or a TAR stream without an end-of-archive marker). It comes with a
/// Medium issue, so the overall status is at least `WARNING`; exit code 0 does
/// not mean integrity `OK`.
///
/// # Errors
///
/// As [`verify_archive`]. With integrity requested, a TAR entry whose content
/// fails to decode, or whose data is cut short, is an
/// [`ArchiveError::InvalidArchive`]: the
/// scan cannot continue past it, and a report over the entries read so far
/// would let security look fine for entries never inspected. Corruption in a
/// TAR trailer (a gzip CRC, an xz index) is a `FAILED` report instead.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::DecompressionBudget;
/// use exarch_core::IntegrityCheck;
/// use exarch_core::IntegrityStatus;
/// use exarch_core::SecurityConfig;
/// use exarch_core::VerificationOptions;
/// use exarch_core::verify_archive_with_options;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let options = VerificationOptions::default()
///     .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
/// let report = verify_archive_with_options("archive.zip", &SecurityConfig::default(), &options)?;
/// if report.integrity_status() == IntegrityStatus::Fail {
///     eprintln!("archive is corrupt");
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify_archive_with_options<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
    options: &VerificationOptions,
) -> Result<VerificationReport> {
    let validated_config = config.clone().validate()?;
    let archive_path = archive_path.as_ref();
    let format = detect_format(archive_path)?;
    match format.family() {
        FormatFamily::Zip => {
            let file = std::fs::File::open(archive_path)?;
            return ZipArchive::new(file)?.verify(&validated_config, options);
        }
        FormatFamily::SevenZ => {
            let file = std::fs::File::open(archive_path)?;
            return SevenZArchive::new(file)?.verify(&validated_config, options);
        }
        FormatFamily::Tar(_) => {}
    }
    verify_with(&validated_config, *options, |listing| {
        list_detected(archive_path, format, &validated_config, listing)
    })
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
                // A target that is not read is never read when symlinks are
                // disallowed, so the policy is the reason to report.
                (if matches!(target, LinkTarget::Unread | LinkTarget::Unreadable) {
                    require_symlinks_allowed(config)
                } else {
                    Ok(())
                })
                .and_then(|()| match target {
                    // Counted once by `unread_targets_issue`; the tree keeps
                    // the link opaque.
                    LinkTarget::Unread => Ok(()),
                    _ => usable_link_target(target, ManifestEntryType::Symlink).and_then(|t| {
                        check_target_lengths(t, LinkKind::Symlink)?;
                        SafeSymlink::validate_in(safe_path, t, dest, config, tree).map(drop)
                    }),
                }),
            ),
            ManifestEntryKind::Hardlink { target } => Some(
                usable_link_target(target, ManifestEntryType::Hardlink).and_then(|t| {
                    check_target_lengths(t, LinkKind::Hardlink)?;
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
                let recorded = record_entry(tree, safe_path.as_path(), &entry.kind);
                issues.extend(collision_issues(tree));
                if let Err(e) = recorded {
                    let error = insert_failure(tree, dest, safe_path.as_path(), &entry.kind, e);
                    issues.push(VerificationIssue::from_error(
                        &error,
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

/// Most over-long entries reported one by one; the rest are counted in a
/// closing issue so a hostile archive cannot inflate the report.
const OVERSIZED_ISSUE_CAP: usize = 16;

fn oversized_entry_issues(oversized: &[OversizedEntry]) -> Vec<VerificationIssue> {
    let name_too_long_issue = |detail: String| {
        let error = ArchiveError::Io(std::io::Error::new(
            name_too_long().kind(),
            format!("{}: {detail}", name_too_long()),
        ));
        VerificationIssue::from_error(&error, None)
    };
    let mut issues: Vec<_> = oversized
        .iter()
        .take(OVERSIZED_ISSUE_CAP)
        .map(|entry| {
            name_too_long_issue(format!(
                "entry {} has a path of {} bytes",
                entry.index, entry.bytes
            ))
        })
        .collect();
    let omitted = oversized.len().saturating_sub(OVERSIZED_ISSUE_CAP);
    if omitted > 0 {
        issues.push(name_too_long_issue(format!(
            "{omitted} more entries have over-long paths (first {OVERSIZED_ISSUE_CAP} listed)"
        )));
    }
    issues
}

fn check_target_lengths(target: &Path, kind: LinkKind) -> Result<()> {
    check_link_target_length(target, kind).map_err(ArchiveError::Io)
}

/// Returns the target to validate, or the error a missing or oversized
/// target is reported as.
fn usable_link_target(target: &LinkTarget, kind: ManifestEntryType) -> Result<&Path> {
    match target {
        LinkTarget::Recorded(path) => Ok(path),
        LinkTarget::Missing => Err(missing_link_target(kind)),
        LinkTarget::Unread => Err(unread_link_target(kind)),
        LinkTarget::Unreadable => Err(unreadable_link_target(kind)),
        LinkTarget::Oversized { .. } => Err(ArchiveError::Io(name_too_long())),
    }
}

/// Drains the name collisions the tree recorded since the last call into
/// report issues, so none is lost whichever insert produced it.
fn collision_issues(tree: &mut VirtualTree) -> Vec<VerificationIssue> {
    tree.take_collisions()
        .into_iter()
        .map(collision_issue)
        .collect()
}

/// Spells a path with combining marks and control characters escaped, so two
/// canonically equivalent names do not read as the same text.
fn escaped(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .flat_map(char::escape_debug)
        .collect()
}

fn collision_issue(collision: NameCollision) -> VerificationIssue {
    let severity = match collision.kind {
        CollisionKind::Directories => IssueSeverity::Low,
        CollisionKind::DirectoriesWithContents | CollisionKind::Files => IssueSeverity::Medium,
        CollisionKind::Mixed => IssueSeverity::High,
    };
    VerificationIssue {
        severity,
        category: IssueCategory::NameCollision,
        message: format!(
            "Names \"{}\" and \"{}\" are the same name on case-insensitive or normalizing \
             filesystems",
            escaped(&collision.existing),
            escaped(&collision.incoming)
        ),
        entry_path: Some(collision.incoming),
        context: None,
    }
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
        ManifestEntryKind::Symlink {
            target: LinkTarget::Recorded(t),
        } => Node::Symlink(t.clone()),
        ManifestEntryKind::Symlink {
            target: LinkTarget::Unread,
        } => Node::OpaqueSymlink,
        ManifestEntryKind::Symlink { .. } | ManifestEntryKind::Hardlink { .. } => {
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
        target: LinkTarget::Recorded(target),
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
    tree.insert(link_path.as_path(), Node::File)
        .map_err(|e| insert_failure(tree, dest, link_path.as_path(), &entry.kind, e))
}

/// Classifies a failed tree insert. A failure that involves a link (the entry
/// is one, or the path crosses or lands on one) depends on how extraction
/// resolves the link, so it is a security finding; any other failure is a
/// structural problem of the archive.
fn insert_failure(
    tree: &VirtualTree,
    dest: &DestDir,
    rel: &Path,
    kind: &ManifestEntryKind,
    error: std::io::Error,
) -> ArchiveError {
    let crosses_link = || {
        rel.ancestors()
            .take_while(|p| !p.as_os_str().is_empty())
            .any(|p| tree.is_symlink(&dest.as_path().join(p)).unwrap_or(false))
    };
    if !kind.is_link() && !crosses_link() {
        return ArchiveError::Io(error);
    }
    // A symlink over an existing entry is skipped by default, so only that
    // case depends on the options; the other shapes fail under every set.
    let skipped_by_default = matches!(kind, ManifestEntryKind::Symlink { .. })
        && error.kind() == std::io::ErrorKind::AlreadyExists;
    let when = if skipped_by_default {
        "can fail"
    } else {
        "fails"
    };
    let unless = if skipped_by_default {
        " unless duplicates are skipped"
    } else {
        ""
    };
    ArchiveError::SecurityViolation {
        reason: format!("extraction {when} at {}{unless}: {error}", rel.display()),
    }
}

fn missing_link_target(kind: ManifestEntryType) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!("{} target is missing", kind.as_str().to_ascii_lowercase()),
    }
}

fn unread_link_target(kind: ManifestEntryType) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!(
            "{} target was not read, so it cannot be validated",
            kind.as_str().to_ascii_lowercase()
        ),
    }
}

fn unreadable_link_target(kind: ManifestEntryType) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!(
            "{} target could not be read, so it cannot be validated",
            kind.as_str().to_ascii_lowercase()
        ),
    }
}

/// The one issue for the symlinks whose targets were not read although
/// symlinks are allowed, which `verify_entry` could not validate.
fn unread_targets_issue(
    manifest: &ArchiveManifest,
    config: &SecurityConfig<Validated>,
) -> Option<VerificationIssue> {
    if !config.allowed.symlinks {
        return None;
    }
    let unread = manifest
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind,
                ManifestEntryKind::Symlink {
                    target: LinkTarget::Unread
                }
            )
        })
        .count();
    let (subject, validated) = match unread {
        0 => return None,
        1 => ("symlink target was", "it was"),
        _ => ("symlink targets were", "they were"),
    };
    Some(VerificationIssue::new(
        IssueSeverity::Medium,
        IssueCategory::SecurityPolicy,
        format!(
            "{unread} {subject} not read, so {validated} not validated; entries beneath or \
             through an unread link are reported as failures (an integrity check with a \
             decompression budget that covers the link blocks reads the targets)"
        ),
    ))
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
    use crate::inspection::report::CheckStatus;
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
            target: LinkTarget::Recorded(PathBuf::from(target)),
        }
    }

    fn hardlink_to(target: &str) -> ManifestEntryKind {
        ManifestEntryKind::Hardlink {
            target: LinkTarget::Recorded(PathBuf::from(target)),
        }
    }

    fn assert_link_placement_finding(entries: Vec<(&str, ManifestEntryKind)>, expected: &str) {
        let report = verify_manifest(&manifest_of(entries), &link_config(), None).unwrap();
        assert_ne!(report.security_status(), CheckStatus::Pass);
        let issue = report
            .issues()
            .iter()
            .find(|i| i.category == IssueCategory::SecurityPolicy)
            .unwrap_or_else(|| panic!("no SecurityPolicy issue: {:?}", report.issues()));
        assert_eq!(issue.severity, IssueSeverity::High);
        assert!(issue.message.contains(expected), "{}", issue.message);
    }

    #[test]
    fn dangling_link_used_as_a_parent_fails_the_security_status() {
        assert_link_placement_finding(
            vec![("d", symlink_to("sub")), ("d/f", ManifestEntryKind::File)],
            "extraction fails at d/f:",
        );
    }

    #[test]
    fn symlink_over_an_implicit_dir_fails_the_security_status() {
        assert_link_placement_finding(
            vec![
                ("sub", ManifestEntryKind::Directory),
                ("d/f", ManifestEntryKind::File),
                ("d", symlink_to("sub")),
            ],
            "extraction can fail at d unless duplicates are skipped:",
        );
    }

    #[test]
    fn hardlink_below_a_dangling_link_fails_the_security_status() {
        assert_link_placement_finding(
            vec![
                ("d", symlink_to("sub")),
                ("t", ManifestEntryKind::File),
                ("d/h", hardlink_to("t")),
            ],
            "extraction fails at d/h:",
        );
    }

    #[test]
    fn directory_over_a_file_is_not_a_security_finding() {
        let manifest = manifest_of(vec![
            ("a", ManifestEntryKind::File),
            ("a", ManifestEntryKind::Directory),
        ]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        assert_eq!(report.security_status(), CheckStatus::Pass);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::InvalidArchive)
        );
    }

    #[test]
    fn overlong_link_targets_are_reported_without_resolution() {
        let long = "a".repeat(1 << 20);
        let manifest = manifest_of(vec![
            ("s", symlink_to(&long)),
            ("t", ManifestEntryKind::File),
            ("h", hardlink_to(&long)),
        ]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        let too_long = report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::InvalidArchive)
            .count();
        assert_eq!(too_long, 2, "{:?}", report.issues());
    }

    fn unread_symlink() -> ManifestEntryKind {
        ManifestEntryKind::Symlink {
            target: LinkTarget::Unread,
        }
    }

    #[test]
    fn unread_symlinks_warn_once_and_report_what_runs_through_them() {
        let alone = manifest_of(vec![("d", unread_symlink()), ("e", unread_symlink())]);
        let report = verify_manifest(&alone, &link_config(), None).unwrap();
        assert_eq!(report.status(), VerificationStatus::Warning);
        assert_eq!(report.issues().len(), 1, "{:?}", report.issues());

        for entries in [
            vec![("d", unread_symlink()), ("d/f", ManifestEntryKind::File)],
            vec![("d", unread_symlink()), ("l", symlink_to("d/x"))],
            vec![("d", unread_symlink()), ("l", symlink_to("d"))],
        ] {
            let manifest = manifest_of(entries);
            let report = verify_manifest(&manifest, &link_config(), None).unwrap();
            assert_eq!(report.status(), VerificationStatus::Fail, "{manifest:?}");
        }
    }

    #[test]
    fn unread_symlinks_are_a_policy_failure_when_symlinks_are_disallowed() {
        let manifest = manifest_of(vec![("d", unread_symlink())]);
        let config = SecurityConfig::default().validate().unwrap();
        let report = verify_manifest(&manifest, &config, None).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert_eq!(report.issues().len(), 1, "{:?}", report.issues());
    }

    #[test]
    fn unreadable_symlinks_fail_without_a_warning_count() {
        let manifest = manifest_of(vec![(
            "d",
            ManifestEntryKind::Symlink {
                target: LinkTarget::Unreadable,
            },
        )]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert_eq!(report.issues().len(), 1, "{:?}", report.issues());
        assert!(report.issues()[0].message.contains("could not be read"));
    }

    #[test]
    fn oversized_link_targets_from_the_preflight_are_reported() {
        let manifest = manifest_of(vec![
            (
                "s",
                ManifestEntryKind::Symlink {
                    target: LinkTarget::Oversized { bytes: 100_000 },
                },
            ),
            (
                "h",
                ManifestEntryKind::Hardlink {
                    target: LinkTarget::Oversized { bytes: 100_000 },
                },
            ),
        ]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        let too_long = report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::InvalidArchive)
            .count();
        assert_eq!(too_long, 2, "{:?}", report.issues());
        assert_eq!(report.status(), VerificationStatus::Fail);
    }

    #[test]
    fn collision_severity_follows_the_kinds_involved() {
        let collision = |kind| NameCollision {
            existing: PathBuf::from("a"),
            incoming: PathBuf::from("A"),
            kind,
        };
        let severity = |kind| collision_issue(collision(kind)).severity;
        assert_eq!(severity(CollisionKind::Directories), IssueSeverity::Low);
        assert_eq!(
            severity(CollisionKind::DirectoriesWithContents),
            IssueSeverity::Medium
        );
        assert_eq!(severity(CollisionKind::Files), IssueSeverity::Medium);
        assert_eq!(severity(CollisionKind::Mixed), IssueSeverity::High);
    }

    fn ascii_upper(name: &std::ffi::OsStr) -> std::borrow::Cow<'_, std::ffi::OsStr> {
        std::borrow::Cow::Owned(name.to_string_lossy().to_ascii_uppercase().into())
    }

    /// Verifies as a host that compares names case-insensitively would.
    fn verify_folding(entries: Vec<(&str, ManifestEntryKind)>) -> VerificationReport {
        let manifest = manifest_of(entries);
        verify_with_tree(
            &manifest,
            &link_config(),
            &ArchiveStructure::of_manifest(&manifest),
            None,
            |root| VirtualTree::with_fold(root, ascii_upper),
        )
        .unwrap()
    }

    fn collisions(report: &VerificationReport) -> Vec<IssueSeverity> {
        report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::NameCollision)
            .map(|i| i.severity)
            .collect()
    }

    #[test]
    fn hardlink_over_differently_spelled_file_is_not_a_pass() {
        let report = verify_folding(vec![
            ("a.txt", ManifestEntryKind::File),
            ("A.txt", hardlink_to("a.txt")),
        ]);
        assert_ne!(report.status(), VerificationStatus::Pass);
        assert_eq!(collisions(&report), [IssueSeverity::Medium]);
    }

    #[test]
    fn symlink_over_differently_spelled_file_is_reported_as_mixed() {
        let report = verify_folding(vec![("a", ManifestEntryKind::File), ("A", symlink_to("x"))]);
        assert!(collisions(&report).contains(&IssueSeverity::High));
        assert_eq!(report.status(), VerificationStatus::Fail);
    }

    #[test]
    fn differently_spelled_files_and_directories_with_contents_are_reported() {
        let report = verify_folding(vec![
            ("Images/x", ManifestEntryKind::File),
            ("images/y", ManifestEntryKind::File),
            ("f", ManifestEntryKind::File),
            ("F", ManifestEntryKind::File),
        ]);
        assert_eq!(
            collisions(&report),
            [IssueSeverity::Medium, IssueSeverity::Medium]
        );
        assert_eq!(report.status(), VerificationStatus::Warning);
    }

    #[test]
    fn merged_directories_with_colliding_children_are_never_a_pass() {
        let entries: Vec<_> = (0..50)
            .flat_map(|i| {
                [
                    (format!("a/f{i}"), ManifestEntryKind::File),
                    (format!("A/f{i}"), ManifestEntryKind::File),
                ]
            })
            .collect();
        let manifest = manifest_of(
            entries
                .iter()
                .map(|(p, k)| (p.as_str(), k.clone()))
                .collect(),
        );
        let report = verify_with_tree(
            &manifest,
            &link_config(),
            &ArchiveStructure::of_manifest(&manifest),
            None,
            |root| VirtualTree::with_fold(root, ascii_upper),
        )
        .unwrap();
        assert_eq!(report.status(), VerificationStatus::Warning);
        assert_eq!(report.security_status(), crate::CheckStatus::Warning);
        assert_eq!(
            collisions(&report),
            [IssueSeverity::Medium],
            "reported once"
        );
    }

    #[test]
    fn merged_empty_directories_are_low_and_keep_security_ok() {
        let report = verify_folding(vec![
            ("Dir", ManifestEntryKind::Directory),
            ("dir", ManifestEntryKind::Directory),
        ]);
        assert_eq!(collisions(&report), [IssueSeverity::Low]);
        assert_eq!(report.status(), VerificationStatus::Pass);
        assert_eq!(report.security_status(), crate::CheckStatus::Pass);
    }

    #[test]
    fn empty_directory_merge_is_upgraded_when_an_entry_lands_in_it() {
        let report = verify_folding(vec![
            ("Dir", ManifestEntryKind::Directory),
            ("dir", ManifestEntryKind::Directory),
            ("Dir/f", ManifestEntryKind::File),
        ]);
        assert_eq!(collisions(&report), [IssueSeverity::Medium]);
        assert_eq!(report.status(), VerificationStatus::Warning);
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
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        assert!(report.issues().is_empty(), "{:?}", report.issues());
    }

    #[test]
    fn phase_two_reports_absent_hardlink_target() {
        let manifest = manifest_of(vec![("h", hardlink_to("missing"))]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
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
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
        assert!(report.issues().is_empty(), "{:?}", report.issues());
    }

    #[test]
    fn phase_one_failure_is_not_reported_again_in_phase_two() {
        let manifest = manifest_of(vec![
            ("t", ManifestEntryKind::File),
            ("h", hardlink_to("../outside")),
        ]);
        let report = verify_manifest(&manifest, &link_config(), None).unwrap();
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

    #[test]
    fn xl_type_divergence_is_bound_to_its_manifest_entry() {
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;
        use crate::raw_zip::SYMLINK_MODE;
        use crate::raw_zip::XL_FIELD_ID;
        use crate::raw_zip::xl_unix_attributes;

        let built = RawZip::new(vec![
            RawEntry::stored("a.txt", b"../../../../tmp/pwned")
                .with_local_unix_host()
                .with_local_extra_field(XL_FIELD_ID, &xl_unix_attributes(SYMLINK_MODE)),
            RawEntry::stored("b.txt", b"plain b\n"),
        ])
        .build();
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&built.bytes).unwrap();
        temp_file.flush().unwrap();

        let report = verify_archive(temp_file.path(), &SecurityConfig::default()).unwrap();

        assert_eq!(report.suspicious_entries(), 1);
        let issue = report
            .issues()
            .iter()
            .find(|i| i.message.contains("xl extra field"))
            .unwrap();
        assert_eq!(issue.entry_path.as_deref(), Some(Path::new("a.txt")));
    }

    #[test]
    fn zip_finding_after_a_dropped_oversized_entry_names_its_own_entry() {
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;
        use crate::raw_zip::SYMLINK_MODE;
        use crate::raw_zip::XL_FIELD_ID;
        use crate::raw_zip::xl_unix_attributes;

        let long_name = "n".repeat(304);
        let built = RawZip::new(vec![
            RawEntry::stored(&long_name, b"long"),
            RawEntry::stored("a.txt", b"../../../../tmp/pwned")
                .with_local_unix_host()
                .with_local_extra_field(XL_FIELD_ID, &xl_unix_attributes(SYMLINK_MODE)),
            RawEntry::stored("b.txt", b"plain b\n"),
        ])
        .build();
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&built.bytes).unwrap();
        temp_file.flush().unwrap();

        let report = verify_archive(temp_file.path(), &SecurityConfig::default()).unwrap();

        let issue = report
            .issues()
            .iter()
            .find(|i| i.message.contains("xl extra field"))
            .unwrap();
        assert_eq!(issue.entry_path.as_deref(), Some(Path::new("a.txt")));
    }

    #[test]
    fn descriptor_overrun_is_bound_to_its_manifest_entry() {
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;

        let built = RawZip::new(vec![
            RawEntry::stored("p.txt", b"plain p\n"),
            RawEntry::stored("a.txt", b"stored a\n").with_descriptor(false, false),
            RawEntry::stored("b.txt", b"stored b\n"),
            RawEntry::stored("c.txt", b"stored c\n"),
        ])
        .build();
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&built.bytes).unwrap();
        temp_file.flush().unwrap();

        let report = verify_archive(temp_file.path(), &SecurityConfig::default()).unwrap();

        assert_eq!(report.suspicious_entries(), 1);
        let issue = report
            .issues()
            .iter()
            .find(|i| i.message.contains("data descriptor of entry 1"))
            .unwrap();
        assert_eq!(issue.entry_path.as_deref(), Some(Path::new("a.txt")));
    }

    // Regression test: verify_archive() must report an oversized entry as a
    // graceful VerificationIssue (Fail status with an itemized report), not
    // abort with a bare error during its internal pre-flight list_archive()
    // call. Before the pre-flight lifted the per-file limit, list_archive()
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

    // #430: a NUL-byte entry path must surface as a VerificationIssue, not a
    // hard `Err` from the verify pre-flight listing.
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
    // `inspection::list::tests`). `ListPass::VerifyPreflight` lets the
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

    fn cloaked_zip_file() -> NamedTempFile {
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;

        let bytes = RawZip::new(vec![
            RawEntry::stored("cron_worker.sh", b"payload").with_central_name("doc_report.pdf"),
        ])
        .build()
        .bytes;
        let mut file = NamedTempFile::with_suffix(".zip").unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn verify_archive_fails_a_cloaked_zip_under_the_default_policy() {
        let file = cloaked_zip_file();
        let report = verify_archive(file.path(), &SecurityConfig::default()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert_eq!(report.security_status(), crate::CheckStatus::Fail);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::HeaderMismatch)
        );
        assert_eq!(report.total_entries(), 1);
    }

    #[test]
    fn verify_archive_passes_a_cloaked_zip_when_ignored() {
        use crate::ZipConsistencyPolicy;

        let file = cloaked_zip_file();
        let config = SecurityConfig::default().with_zip_consistency(ZipConsistencyPolicy::Ignore);
        let report = verify_archive(file.path(), &config).unwrap();
        assert_eq!(report.status(), VerificationStatus::Pass);
    }

    #[test]
    fn permissive_config_enforces_zip_consistency_too() {
        let file = cloaked_zip_file();
        let report = verify_archive(file.path(), &SecurityConfig::permissive()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
    }

    #[test]
    fn verify_archive_reports_an_oversized_zip_symlink_target() {
        use crate::test_utils::HOST_SYMLINK_TARGET_BYTES;
        use crate::test_utils::create_zip_with_symlink;

        let bytes = create_zip_with_symlink("link", &"a".repeat(HOST_SYMLINK_TARGET_BYTES + 1));
        let mut file = NamedTempFile::with_suffix(".zip").unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_symlinks(true);
        let report = verify_archive(file.path(), &config)
            .expect("an oversized target is a report issue, not an error");
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::InvalidArchive
                    && i.message.contains("file name too long")),
            "{:?}",
            report.issues()
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
