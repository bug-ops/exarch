//! Hardlink security validation and tracking.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::Malformation;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::security::fs_view::FsView;
#[cfg(any(test, feature = "testing"))]
use crate::security::fs_view::HostFs;
use crate::security::fs_view::LinkBase;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::ModelRoot;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
#[cfg(any(test, feature = "testing"))]
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::dest_dir::ProbePath;
use crate::types::safe_path::ParentCheck;
use crate::types::safe_path::check_component_for;
use crate::types::safe_symlink::has_root_or_prefix;

/// Error for a hardlink whose target is absent when the link is created.
pub(crate) fn hardlink_target_missing(target: &Path) -> ArchiveError {
    ArchiveError::from(Malformation::HardlinkTargetAbsent {
        target: target.to_path_buf(),
    })
}

/// Fails with the hardlink-policy refusal unless `config` allows hardlinks.
///
/// # Errors
///
/// Returns `SecurityViolation` ("hardlinks not allowed") when hardlinks are
/// disabled.
pub(crate) fn require_hardlinks_allowed(config: &SecurityConfig) -> Result<()> {
    config
        .allowed
        .hardlinks
        .is_allowed()
        .ok_or_else(|| Violation::LinksNotAllowed(LinkKind::Hardlink).into())
}

/// Fails unless a file lands at `target` in `tree`: nothing there is
/// [`Malformation::HardlinkTargetAbsent`], a directory is
/// [`Malformation::HardlinkTargetDirectory`].
///
/// # Errors
///
/// Returns [`Malformation::HardlinkTargetAbsent`] when nothing lands at
/// `target` in `tree`, and [`Malformation::HardlinkTargetDirectory`] when the
/// path resolves to a directory.
pub(crate) fn require_target_present(
    target: &Path,
    root: &VirtualRoot,
    tree: &VirtualTree,
) -> Result<()> {
    let target_full = root.as_path().join(target);
    if !tree.exists(&target_full) {
        return Err(hardlink_target_missing(target));
    }
    if tree.resolves_to_dir(&target_full) {
        return Err(Malformation::HardlinkTargetDirectory {
            target: target.to_path_buf(),
        }
        .into());
    }
    Ok(())
}

/// A hardlink target that passed `HardlinkTracker` validation.
///
/// The path is relative, non-empty and free of NUL bytes, root and prefix
/// components; every normal component passed the component checks, and the
/// target resolved inside the extraction root when it was validated. It may
/// contain `..` components that stay inside the root, and it is re-resolved
/// when opened in the second extraction pass, so it names a lexical location,
/// not a proof about what is on disk at that time.
///
/// There is no public constructor: the only producer is
/// `HardlinkTracker`'s validation, so a hardlink target cannot be assembled
/// from an unchecked path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardlinkTarget(PathBuf);

impl HardlinkTarget {
    /// Returns the validated target, relative to the destination directory.
    #[inline]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Whether the target steps out of a directory it entered (`d/../f`).
    #[must_use]
    pub fn has_parent_dir(&self) -> bool {
        self.0
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    }

    /// Names the target below `dest` for a read-only probe.
    #[must_use]
    pub(crate) fn probe_under(&self, dest: &crate::types::DestDir) -> ProbePath {
        dest.probe(&self.0)
    }

    /// Read-only probes of the target's parent directories below `dest`,
    /// outermost first.
    pub(crate) fn parent_probes<'a>(
        &'a self,
        dest: &'a crate::types::DestDir,
    ) -> impl Iterator<Item = ProbePath> + 'a {
        let mut prefix = PathBuf::new();
        self.0
            .parent()
            .into_iter()
            .flat_map(Path::components)
            .map(move |component| {
                prefix.push(component);
                dest.probe(&prefix)
            })
    }
}

/// Tracks hardlink targets during extraction.
///
/// Hardlinks in archives can be used for attacks:
/// 1. Link to files outside the extraction directory
/// 2. Create multiple hardlinks to the same file (resource exhaustion)
/// 3. Link to sensitive files (if absolute paths allowed)
///
/// This tracker ensures:
/// - Hardlinks are allowed in the security configuration
/// - Targets are relative paths
/// - Targets resolve within the destination directory
/// - Duplicate hardlinks are detected
///
/// # Two-Pass Validation
///
/// Hardlinks require two-pass validation:
/// 1. **First pass (during validation):** Track target paths, verify they're
///    within bounds
/// 2. **Second pass (after extraction):** Verify targets actually exist
///
/// This is necessary because hardlink targets may appear later in the archive.
///
/// # Examples
///
/// ```ignore
/// use exarch_core::SecurityConfig;
/// use exarch_core::HardlinkTracker;
/// use exarch_core::DestDir;
/// use exarch_core::SafePath;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.hardlinks = exarch_core::Admit::Allow;
///
/// let mut tracker = HardlinkTracker::new();
/// let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)?;
/// let target = Path::new("target.txt");
///
/// tracker.validate_hardlink(&link, target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
#[cfg_attr(not(feature = "testing"), allow(unreachable_pub))]
pub struct HardlinkTracker {
    /// Maps target path to the first link path that referenced it
    seen_targets: HashMap<PathBuf, PathBuf>,
}

#[cfg_attr(not(feature = "testing"), allow(unreachable_pub))]
impl HardlinkTracker {
    /// Creates a new hardlink tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen_targets: HashMap::new(),
        }
    }

    /// Validates that a hardlink target is safe and tracks it.
    ///
    /// # Performance
    ///
    /// Typical execution time: ~1-5 μs (`HashMap` insert + path validation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hardlinks are not allowed in configuration
    /// - Target is empty or contains NUL bytes
    /// - Target is an absolute path (including Windows drive/UNC prefixes)
    /// - Target would escape the destination directory
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::HardlinkTracker;
    /// use exarch_core::DestDir;
    /// use exarch_core::SafePath;
    /// use std::path::Path;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let mut config = SecurityConfig::default();
    /// config.allowed.hardlinks = exarch_core::Admit::Allow;
    ///
    /// let mut tracker = HardlinkTracker::new();
    /// let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)?;
    /// let target = Path::new("target.txt");
    ///
    /// tracker.validate_hardlink(&link, target, &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(any(test, feature = "testing"))]
    pub fn validate_hardlink(
        &mut self,
        link_path: &SafePath,
        target: &Path,
        dest: &DestDir,
        config: &SecurityConfig,
    ) -> Result<HardlinkTarget> {
        self.validate_hardlink_in(link_path, target, dest, config, &HostFs)
    }

    /// Validates against `view` instead of the real filesystem.
    #[expect(
        clippy::items_after_statements,
        reason = "the import is placed next to its only use"
    )]
    pub(crate) fn validate_hardlink_in<V: FsView, P: ParentCheck>(
        &mut self,
        link_path: &SafePath<P>,
        target: &Path,
        root: &V::Root,
        config: &SecurityConfig,
        view: &V,
    ) -> Result<HardlinkTarget> {
        require_hardlinks_allowed(config)?;

        // Reject empty targets: they do not point anywhere.
        if target.is_empty() {
            return Err(Violation::LinkTargetEmpty(LinkKind::Hardlink).into());
        }

        // Reject null bytes in the target before any error message can be
        // built from it. Without this check, a NUL byte either falls
        // through to the OS as a raw `io::Error`, or gets embedded verbatim
        // into a formatted `InvalidArchive` message further downstream (e.g.
        // "hardlink target does not exist: {target}"). The message here
        // intentionally omits the raw target bytes.
        if crate::types::safe_path::has_null_bytes(target) {
            return Err(Violation::LinkTargetNul(LinkKind::Hardlink).into());
        }

        use std::path::Component;

        // H-SEC-2: Reject Windows-specific absolute path components in target
        // (before resolution) This prevents bypasses on Windows like
        // C:\ or \\server\share
        if has_root_or_prefix(target) {
            return Err(ArchiveError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            });
        }

        for component in target.components() {
            if let Component::Normal(comp) = component {
                check_component_for(view.path_model(), comp, config)?;
            }
        }

        // Also reject absolute targets (redundant with above, but keeps
        // existing check)
        if target.is_absolute() {
            return Err(ArchiveError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            });
        }

        // Resolve target against destination, following any on-disk symlinks
        // encountered during traversal.
        //
        // String-based normalization is insufficient: if a previously extracted
        // symlink lies on the target path, a hardlink target can escape the
        // extraction root via on-disk resolution even though string
        // normalization would pass (two-hop chain bypass,
        // GHSA-83g3-92jg-28cx variant — #116).
        let resolved = view
            .resolve_link_target(link_path.as_path(), target, LinkBase::Destination, root)
            .map_err(|_| ArchiveError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            })?;

        // Track this hardlink target (H-PERF-6: use entry API)
        self.seen_targets
            .entry(resolved)
            .or_insert_with(|| link_path.as_path().to_path_buf());

        Ok(HardlinkTarget(target.to_path_buf()))
    }

    /// Validates a hardlink target against the final tree: the escape checks
    /// of [`validate_hardlink_in`](Self::validate_hardlink_in), then that the
    /// target exists there and is not a directory.
    ///
    /// Used by `verify`, which judges a link once the whole tree is known. The
    /// `list` preview splits the same two steps: the escape checks at the
    /// link's own position, as extraction does, and
    /// [`require_target_present`] once every entry has landed.
    ///
    /// # Errors
    ///
    /// Returns the validation error, [`Malformation::HardlinkTargetAbsent`]
    /// when nothing lands at the target, or
    /// [`Malformation::HardlinkTargetDirectory`] when a directory does.
    pub(crate) fn check_hardlink_target<P: ParentCheck>(
        &mut self,
        link_path: &SafePath<P>,
        target: &Path,
        root: &VirtualRoot,
        config: &SecurityConfig,
        tree: &VirtualTree,
    ) -> Result<()> {
        self.validate_hardlink_in(link_path, target, root, config, tree)?;
        require_target_present(target, root, tree)
    }

    /// Returns the number of tracked hardlinks.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn count(&self) -> usize {
        self.seen_targets.len()
    }
}

#[cfg(test)]
impl HardlinkTracker {
    pub(crate) fn has_target(&self, target: &Path) -> bool {
        self.seen_targets.contains_key(target)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use std::assert_matches;
    use tempfile::TempDir;

    fn create_test_dest() -> (TempDir, DestDir) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        (temp, dest)
    }

    #[test]
    fn test_hardlink_tracker_new() {
        let tracker = HardlinkTracker::new();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_validate_hardlink_allowed() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        assert!(
            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .is_ok()
        );
        assert_eq!(tracker.count(), 1);
    }

    #[test]
    fn test_validate_hardlink_disabled() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default(); // hardlinks disabled by default

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        assert!(
            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .is_err()
        );
    }

    #[test]
    fn test_validate_hardlink_absolute_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("/etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::HardlinkEscape { .. }));
    }

    #[test]
    fn test_validate_hardlink_escape() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("../../etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::HardlinkEscape { .. }));
    }

    #[test]
    fn test_hardlink_tracker_multiple() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();

        let link1 = SafePath::validate(&PathBuf::from("link1"), &dest, &config).unwrap();
        let link2 = SafePath::validate(&PathBuf::from("link2"), &dest, &config).unwrap();

        tracker
            .validate_hardlink(&link1, &PathBuf::from("target1.txt"), &dest, &config)
            .unwrap();
        tracker
            .validate_hardlink(&link2, &PathBuf::from("target2.txt"), &dest, &config)
            .unwrap();

        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn test_hardlink_tracker_has_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        tracker
            .validate_hardlink(&link, &target, &dest, &config)
            .unwrap();

        let resolved_target = dest.as_path().join(&target);
        assert!(tracker.has_target(&resolved_target));
    }

    #[test]
    fn test_hardlink_tracker_relative_safe() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("foo/link"), &dest, &config).unwrap();
        // Safe relative path within destination
        let target = PathBuf::from("target.txt");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validated_target_keeps_the_validated_path_and_reports_parent_dir() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        std::fs::create_dir(dest.as_path().join("d")).unwrap();

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();

        let plain = tracker
            .validate_hardlink(&link, Path::new("d/f"), &dest, &config)
            .unwrap();
        assert_eq!(plain.as_path(), Path::new("d/f"));
        assert!(!plain.has_parent_dir());

        let stepping = tracker
            .validate_hardlink(&link, Path::new("d/../f"), &dest, &config)
            .unwrap();
        assert_eq!(stepping.as_path(), Path::new("d/../f"));
        assert!(stepping.has_parent_dir());
    }

    // H-TEST-2: Duplicate hardlink to same target test
    #[test]
    fn test_duplicate_hardlink_to_same_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();
        let target = PathBuf::from("target.txt");

        // Create multiple hardlinks to the same target
        for i in 0..3 {
            let link =
                SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config).unwrap();

            let result = tracker.validate_hardlink(&link, &target, &dest, &config);
            assert!(
                result.is_ok(),
                "multiple hardlinks to same target should be allowed"
            );
        }

        // All three links point to the same target, so only 1 unique target
        // tracked
        assert_eq!(
            tracker.count(),
            1,
            "should track unique targets, not individual links"
        );
    }

    #[test]
    fn test_hardlink_different_targets() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let mut tracker = HardlinkTracker::new();

        // Create hardlinks to different targets
        for i in 0..3 {
            let link =
                SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config).unwrap();
            let target = PathBuf::from(format!("target{i}.txt"));

            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .unwrap();
        }

        // Three different targets
        assert_eq!(tracker.count(), 3, "should track each unique target");
    }

    /// Hardlink target that traverses through an already-extracted symlink must
    /// be rejected (two-hop chain, GHSA-83g3-92jg-28cx variant — issue #116).
    ///
    /// Entry 2 (symlink a/b/c/up -> ../..) is on disk when hardlink is
    /// validated. Target a/b/escape/../../etc/passwd: string normalization
    /// → dest/a/etc/passwd (looks safe), but if a/b/escape is an on-disk
    /// symlink resolving outside dest, the hardlink must be rejected.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used)]
    fn test_hardlink_two_hop_chain_rejected() {
        use std::fs;
        use std::os::unix;

        let (temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        // Simulate on-disk state after extracting the two symlink entries.
        let a = temp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        fs::create_dir_all(&c).unwrap();
        // a/b/c/up -> ../..  (first hop: resolves to a/)
        unix::fs::symlink("../..", c.join("up")).unwrap();
        // a/b/escape -> c/up/../..  (second hop: resolves outside dest on disk)
        unix::fs::symlink("c/up/../..", b.join("escape")).unwrap();

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("exfil"), &dest, &config).unwrap();
        // Target traverses through the escape symlink
        let target = PathBuf::from("a/b/escape/../../etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::HardlinkEscape { .. }),
            "hardlink through two-hop symlink chain must be rejected"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_hardlink_rejects_windows_hazards_in_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();

        for target in ["dir/foo.", "dir/foo ", "dir/a:b", "sub/NUL"] {
            let mut tracker = HardlinkTracker::new();
            assert_matches!(
                tracker.validate_hardlink(&link, &PathBuf::from(target), &dest, &config),
                Err(ArchiveError::SecurityViolation { .. }),
                "{target}"
            );
        }
    }

    #[test]
    fn test_hardlink_rejects_slash_unc_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();

        assert_matches!(
            HardlinkTracker::new().validate_hardlink(
                &link,
                Path::new("//host/share/x"),
                &dest,
                &config
            ),
            Err(ArchiveError::HardlinkEscape { .. })
        );
    }

    /// Regression for GHSA-5qh5-c9fp-66jm: UNC and device-namespace targets
    /// must be rejected as escapes before any filesystem probe. Unverified
    /// locally; runs only in the Windows CI job.
    #[test]
    #[cfg(windows)]
    fn test_hardlink_rejects_unc_and_device_targets_windows() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();

        for target in [
            r"\\host\share\x",
            "//host/share/x",
            r"\\?\UNC\host\share\x",
            r"\\.\UNC\host\share\x",
            r"\??\UNC\host\share\x",
        ] {
            assert_matches!(
                HardlinkTracker::new().validate_hardlink(
                    &link,
                    &PathBuf::from(target),
                    &dest,
                    &config
                ),
                Err(ArchiveError::HardlinkEscape { .. }),
                "{target}"
            );
        }
    }
}
