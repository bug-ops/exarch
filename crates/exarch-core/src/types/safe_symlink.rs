//! Validated safe symlink type.

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;
use super::SafePath;
use super::safe_path::check_windows_component;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;

/// A validated symlink that is safe for extraction.
///
/// `SafeSymlink` represents a symbolic link where:
/// - The link path is a valid `SafePath`
/// - The target path is relative (not absolute)
/// - The resolved target stays within the destination directory
/// - Symlinks are allowed by the security configuration
///
/// # Security Properties
///
/// - Can ONLY be constructed through validation
/// - NO `From<PathBuf>` implementation (security critical)
/// - Target always resolves within destination directory
/// - Prevents symlink escape attacks
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use exarch_core::types::SafeSymlink;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.symlinks = true;
/// let config = config.validate()?;
///
/// let link = SafePath::validate(&PathBuf::from("mylink"), &dest, &config)?;
/// let target = PathBuf::from("../target.txt");
///
/// let symlink = SafeSymlink::validate(&link, &target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSymlink {
    link_path: PathBuf,
    target_path: PathBuf,
}

impl SafeSymlink {
    /// Validates and constructs a `SafeSymlink`.
    ///
    /// This is the ONLY way to construct a `SafeSymlink`. The validation
    /// process ensures the symlink is safe for extraction.
    ///
    /// # Validation Steps
    ///
    /// 1. Verify symlinks are allowed in the security configuration
    /// 2. Reject an empty target (points nowhere) or a target containing NUL
    ///    bytes
    /// 3. Reject a target containing a `Prefix` or `RootDir` component (e.g.
    ///    Windows `C:\` or `C:foo` drive-relative paths), then validate the
    ///    target is relative (reject absolute symlinks)
    /// 4. Check target components against banned components and
    ///    `max_path_depth`
    /// 5. Verify the link's parent directory chain contains no symlinks (TOCTOU
    ///    protection)
    /// 6. Resolve target against the link's parent directory, following any
    ///    on-disk symlinks encountered; a target whose `..` components cannot
    ///    be resolved against the extracted tree is rejected
    /// 7. Verify resolved target stays within destination directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Symlinks are not allowed by configuration
    /// - Target is empty or contains NUL bytes
    /// - Target is an absolute path, or contains a Windows drive/UNC prefix
    ///   component
    /// - Target contains a banned path component or exceeds `max_path_depth`
    /// - Resolved target escapes the destination directory
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::SafePath;
    /// use exarch_core::types::SafeSymlink;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let mut config = SecurityConfig::default();
    /// config.allowed.symlinks = true;
    /// let config = config.validate()?;
    ///
    /// let link = SafePath::validate(&PathBuf::from("dir/link"), &dest, &config)?;
    /// let target = PathBuf::from("../file.txt");
    ///
    /// let symlink = SafeSymlink::validate(&link, &target, &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(
        link: &SafePath,
        target: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
    ) -> Result<Self> {
        Self::validate_in(link, target, dest, config, &HostFs)
    }

    /// Validates against `view` instead of the real filesystem.
    pub(crate) fn validate_in<V: FsView>(
        link: &SafePath,
        target: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
        view: &V,
    ) -> Result<Self> {
        require_symlinks_allowed(config)?;

        // 1.5. Reject empty targets: an empty target does not point anywhere
        // (some platforms would silently create a dangling symlink); reject
        // it explicitly rather than letting it through.
        if target.is_empty() {
            return Err(ArchiveError::SecurityViolation {
                reason: "symlink target is empty".into(),
            });
        }

        // 1.6. Reject null bytes in the target, matching the same check
        // already applied to the link path. Without this, a NUL byte falls
        // through to the OS and surfaces as a raw `io::Error` instead of a
        // structured `SecurityViolation`. The message intentionally omits
        // the raw target bytes so a NUL byte is never embedded in it.
        if super::safe_path::has_null_bytes(target) {
            return Err(ArchiveError::SecurityViolation {
                reason: "symlink target contains null bytes".into(),
            });
        }

        // H-SEC-2: Reject Windows-specific absolute path components in the
        // target before relying on `is_absolute()` below. On Windows, a
        // drive-relative path like `C:foo` (no backslash after the colon) is
        // not `is_absolute()` per Rust's definition (requires both a prefix
        // AND a root), yet still resolves relative to the current directory
        // on that drive — letting a malicious archive escape via a
        // drive-relative symlink target. Mirrors the identical guard in
        // `HardlinkTracker::validate_hardlink` (`security/hardlink.rs`) and
        // `SafePath::validate` (issue #491, GHSA-9ppj-qmqm-q256 class).
        for component in target.components() {
            if matches!(
                component,
                std::path::Component::Prefix(_) | std::path::Component::RootDir
            ) {
                return Err(ArchiveError::SymlinkEscape {
                    path: link.as_path().to_path_buf(),
                });
            }
        }

        // 2. Validate target is relative (redundant with the check above on
        // Windows, but keeps this check for other absolute-path shapes).
        if target.is_absolute() {
            return Err(ArchiveError::SymlinkEscape {
                path: link.as_path().to_path_buf(),
            });
        }

        // 2.5. Check target for banned components and depth (HIGH-005)
        let mut target_depth = 0;
        for component in target.components() {
            if let std::path::Component::Normal(comp) = component {
                target_depth += 1;
                if cfg!(windows) {
                    check_windows_component(comp, config)?;
                }
                let comp_str = comp.to_string_lossy();
                if !config.is_path_component_allowed(&comp_str) {
                    return Err(ArchiveError::SecurityViolation {
                        reason: format!("symlink target contains banned component: {comp_str}"),
                    });
                }
            }
        }

        // Validate target depth against max_path_depth
        if target_depth > config.max_path_depth {
            return Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "symlink target depth {target_depth} exceeds maximum {}",
                    config.max_path_depth
                ),
            });
        }

        // 3. Verify parent directory chain doesn't contain symlinks (TOCTOU
        //    protection)
        // This prevents race conditions where an attacker replaces a parent
        // directory with a symlink between validation and extraction
        // time.
        verify_parent_not_symlink(link.as_path(), dest, view)?;

        // 4. Resolve target against link's parent directory, following any
        // on-disk symlinks encountered during traversal.
        //
        // String-based normalization is insufficient: a target component that
        // is already a symlink written to disk by a previous entry can redirect
        // subsequent `..` traversal outside the extraction root (two-hop chain,
        // GHSA-83g3-92jg-28cx variant — issue #116).
        let link_parent = link.as_path().parent().unwrap_or_else(|| Path::new(""));
        let link_parent_full = dest.as_path().join(link_parent);
        resolve_through_symlinks_in(
            &link_parent_full,
            target,
            dest.as_path(),
            link.as_path(),
            view,
        )?;

        Ok(Self {
            link_path: link.as_path().to_path_buf(),
            target_path: target.to_path_buf(),
        })
    }

    /// Returns the link path.
    #[inline]
    #[must_use]
    pub fn link_path(&self) -> &Path {
        &self.link_path
    }

    /// Returns the target path.
    ///
    /// Note: This is the relative target path as stored in the symlink,
    /// not the resolved absolute path.
    #[inline]
    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }
}

/// Fails with the symlink-policy refusal unless `config` allows symlinks.
///
/// # Errors
///
/// Returns `SecurityViolation` ("symlinks not allowed") when symlinks are
/// disabled.
pub(crate) fn require_symlinks_allowed(config: &SecurityConfig<Validated>) -> Result<()> {
    if config.allowed.symlinks {
        Ok(())
    } else {
        Err(ArchiveError::SecurityViolation {
            reason: "symlinks not allowed".into(),
        })
    }
}

/// Verifies that no component in the parent directory chain of `path` is a
/// symlink.
///
/// This function provides protection against TOCTOU (Time-Of-Check-Time-Of-Use)
/// race conditions where an attacker could replace a parent directory with a
/// symlink between validation and extraction time.
///
/// # Security Note
///
/// While this check significantly reduces the attack window, it doesn't
/// eliminate TOCTOU risks entirely. For untrusted archives, extraction should
/// always be performed in isolated environments (containers, chroot, etc.).
///
/// # Errors
///
/// Returns `SymlinkEscape` if any parent component is a symlink.
fn verify_parent_not_symlink<V: FsView>(path: &Path, dest: &DestDir, view: &V) -> Result<()> {
    let mut current = dest.as_path().to_path_buf();

    // Walk through each component of the path
    for component in path.components() {
        current.push(component);

        // Check if current path exists and is a symlink
        if view.exists(&current) {
            let is_symlink =
                view.is_symlink(&current)
                    .map_err(|_| ArchiveError::SymlinkEscape {
                        path: path.to_path_buf(),
                    })?;

            if is_symlink {
                return Err(ArchiveError::SymlinkEscape {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(())
}

/// Resolves `target` step by step from `start`, following any on-disk symlinks
/// encountered during traversal and verifying containment within `dest` after
/// every component.
///
/// Unlike pure string normalization, this function calls `fs::canonicalize`
/// whenever it steps into a path that is a symlink on disk. This closes the
/// two-hop symlink chain bypass: a target component that is already a symlink
/// (written by a previous archive entry) is resolved to its real on-disk
/// location before any subsequent `..` traversal is applied.
///
/// A `..` must leave a directory that exists or one of `start`'s own
/// components; any other component cannot be resolved against the extracted
/// tree and is rejected.
///
/// # Errors
///
/// Returns `SymlinkEscape` if:
/// - The resolved path escapes `dest` at any step.
/// - A `..` leaves a component that is neither an existing directory nor part
///   of `start`.
/// - `fs::canonicalize` fails for a symlink component (e.g., `ELOOP` for
///   circular chains).
pub(crate) fn resolve_through_symlinks(
    start: &Path,
    target: &Path,
    dest: &Path,
    link_path: &Path,
) -> Result<PathBuf> {
    resolve_through_symlinks_in(start, target, dest, link_path, &HostFs)
}

/// [`resolve_through_symlinks`] against an arbitrary [`FsView`].
pub(crate) fn resolve_through_symlinks_in<V: FsView>(
    start: &Path,
    target: &Path,
    dest: &Path,
    link_path: &Path,
    view: &V,
) -> Result<PathBuf> {
    let mut current = start.to_path_buf();

    for component in target.components() {
        match component {
            std::path::Component::ParentDir => {
                // If the current accumulated path is an on-disk symlink,
                // resolve it before applying `..` so the pop
                // operates on the real filesystem topology
                // rather than the string representation.
                if view.is_symlink(&current).unwrap_or(false) {
                    current =
                        view.canonicalize(&current)
                            .map_err(|_| ArchiveError::SymlinkEscape {
                                path: link_path.to_path_buf(),
                            })?;
                }
                if !(start.starts_with(&current) || view.is_dir(&current)) || !current.pop() {
                    return Err(ArchiveError::SymlinkEscape {
                        path: link_path.to_path_buf(),
                    });
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                current.push(name);
                // Resolve the component immediately if it is a symlink so that
                // any subsequent `..` steps use the real resolved path.
                if view.is_symlink(&current).unwrap_or(false) {
                    current =
                        view.canonicalize(&current)
                            .map_err(|_| ArchiveError::SymlinkEscape {
                                path: link_path.to_path_buf(),
                            })?;
                }
            }
            _ => {
                current.push(component);
            }
        }

        if !current.starts_with(dest) {
            return Err(ArchiveError::SymlinkEscape {
                path: link_path.to_path_buf(),
            });
        }
    }

    Ok(current)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::assert_matches;
    use tempfile::TempDir;

    /// Creates a temporary directory and wraps it in a `DestDir` for testing.
    ///
    /// Returns tuple of (`TempDir`, `DestDir`). `TempDir` must be kept alive
    /// for the duration of the test to prevent cleanup.
    fn create_test_dest() -> (TempDir, DestDir) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        (temp, dest)
    }

    /// Creates a `SecurityConfig` with symlinks enabled for testing.
    fn create_config_with_symlinks() -> SecurityConfig<Validated> {
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        config.validate().expect("valid config")
    }

    #[test]
    fn test_safe_symlink_valid_internal() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("dir/link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("../file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());

        let symlink = result.expect("symlink should be valid");
        assert_eq!(symlink.link_path(), Path::new("dir/link"));
        assert_eq!(symlink.target_path(), Path::new("../file.txt"));
    }

    #[test]
    fn test_safe_symlink_reject_when_disabled() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = false;
        let config = config.validate().expect("valid config");

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_symlink_reject_absolute_target_unix() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("/etc/passwd");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SymlinkEscape { .. }));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_reject_absolute_target_windows() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("C:\\Windows\\System32");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SymlinkEscape { .. }));
    }

    /// Behavior test for issue #491 (GHSA-9ppj-qmqm-q256 class): a Windows
    /// drive-relative target like `C:foo` (no backslash after the colon) is
    /// NOT `is_absolute()` per Rust's definition, which requires both a
    /// `Prefix` AND a `RootDir` component, yet still resolves relative to
    /// the current directory on that drive.
    ///
    /// This test alone does NOT prove the new `Component::Prefix` guard is
    /// what rejects it: pre-fix, `C:foo` was already rejected with the same
    /// `SymlinkEscape` variant via `resolve_through_symlinks`'s `_ =>
    /// current.push(component)` fallback arm, since Windows `PathBuf::push`
    /// with a prefix-but-no-root component replaces `current` entirely
    /// (`current` becomes `"C:"`), which then fails
    /// `current.starts_with(dest)`. See
    /// `test_safe_symlink_reject_drive_relative_target_with_banned_component_windows`
    /// below for the discriminating regression test. `Component::Prefix` can
    /// only be produced by the path parser on Windows, so this test is
    /// `cfg(windows)`-gated (mirrors
    /// `inspection::list::test_contains_traversal_prefix_gated_by_flag`).
    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_reject_drive_relative_target_windows_behavior() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("C:foo");
        assert!(
            !target.is_absolute(),
            "C:foo must not be is_absolute() per Rust's definition — this is the exact gap #491 closes"
        );
        assert!(
            target
                .components()
                .any(|c| matches!(c, std::path::Component::Prefix(_))),
            "C:foo must parse to a Prefix component on Windows"
        );

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "drive-relative symlink target must be rejected, got: {result:?}"
        );
    }

    /// Discriminating regression test for issue #491: unlike the plain
    /// `C:foo` behavior test above, this target is chosen so pre-fix and
    /// post-fix code paths disagree on the *error variant* returned, proving
    /// the new `Component::Prefix` guard — not
    /// `resolve_through_symlinks`'s unrelated fallback rejection — is what
    /// fires.
    ///
    /// `C:.git\evil` is drive-relative (`Prefix` component, no `RootDir`,
    /// same as `C:foo`) but its second component, `.git`, is also a default
    /// `banned_path_components` entry (`SecurityConfig::default()`,
    /// `config.rs:218`). Pre-fix, the old code's `Component::Normal`-only
    /// scan (step 2.5) would reach `.git` first — since the pre-fix code had
    /// no `Prefix` guard ahead of it — and reject with
    /// `SecurityViolation("banned component")`, never reaching
    /// `resolve_through_symlinks` at all. Post-fix, the new guard runs
    /// first and rejects with `SymlinkEscape` before the banned-component
    /// scan is ever reached. Reverting the new guard flips this test's
    /// expected variant from `SymlinkEscape` to `SecurityViolation`, so it
    /// fails closed if the guard regresses.
    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_reject_drive_relative_target_with_banned_component_windows() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from(r"C:.git\evil");
        assert!(
            !target.is_absolute(),
            "C:.git\\evil must not be is_absolute() — drive-relative, no RootDir"
        );

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "drive-relative target with a banned second component must be rejected by the new \
             Prefix guard (SymlinkEscape), not fall through to the banned-component scan \
             (SecurityViolation) — got: {result:?}"
        );
    }

    /// Companion to the drive-relative regression test above, for the other
    /// half of the `Component::Prefix(_) | Component::RootDir` guard: a
    /// Windows root-relative target (`RootDir` with no `Prefix`, e.g.
    /// `\evil`) resolves relative to the current drive and is also NOT
    /// `is_absolute()` per Rust's definition (which requires both a prefix
    /// AND a root). This is a second, previously-untested gap the #491 fix
    /// closes, not just the drive-relative one.
    ///
    /// Uses the same banned-component discriminator as the drive-relative
    /// case above: pre-fix, `.git` is reached by the old Normal-only scan
    /// and rejected as `SecurityViolation`; post-fix, the new `RootDir` arm
    /// fires first and rejects as `SymlinkEscape`.
    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_reject_root_relative_target_with_banned_component_windows() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from(r"\.git\evil");
        assert!(
            !target.is_absolute(),
            r"\.git\evil must not be is_absolute() — RootDir without a Prefix"
        );
        assert!(
            target
                .components()
                .any(|c| matches!(c, std::path::Component::RootDir))
                && !target
                    .components()
                    .any(|c| matches!(c, std::path::Component::Prefix(_))),
            r"\.git\evil must parse to RootDir without Prefix on Windows"
        );

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "root-relative target with a banned second component must be rejected by the new \
             RootDir guard (SymlinkEscape), not fall through to the banned-component scan \
             (SecurityViolation) — got: {result:?}"
        );
    }

    #[test]
    fn test_safe_symlink_reject_external_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("deep/nested/link"), &dest, &config)
            .expect("link path should be valid");

        // Try to escape via multiple ..
        let target = PathBuf::from("../../../../etc/passwd");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SymlinkEscape { .. }));
    }

    #[test]
    fn test_safe_symlink_relative_resolution() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create a link in a subdirectory pointing to a file in parent
        let link = SafePath::validate(&PathBuf::from("subdir/link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("../file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_symlink_complex_relative_path() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/c/link"), &dest, &config)
            .expect("link path should be valid");

        // Target goes up and back down
        let target = PathBuf::from("../../d/e/file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_symlink_equality() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink1 =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");

        let link2 = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let symlink2 = SafeSymlink::validate(&link2, &target, &dest, &config)
            .expect("symlink should be valid");

        assert_eq!(symlink1, symlink2);
    }

    #[test]
    fn test_safe_symlink_clone() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");
        let cloned = symlink.clone();

        assert_eq!(symlink, cloned);
    }

    // M-6: Test for symlink to non-existent internal target
    #[test]
    fn test_safe_symlink_to_nonexistent_internal_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Target doesn't exist but is internal
        let target = PathBuf::from("nonexistent_file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "symlink to internal non-existent target should be allowed"
        );
    }

    // Test for circular symlink detection
    #[test]
    #[allow(clippy::unwrap_used)]
    #[cfg(unix)]
    fn test_circular_symlink_chains() {
        let (temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create actual symlinks for circular chain
        // a -> b, b -> c, c -> a
        let a_path = temp.path().join("a");
        let b_path = temp.path().join("b");
        let c_path = temp.path().join("c");

        std::os::unix::fs::symlink("b", &a_path).unwrap();
        std::os::unix::fs::symlink("c", &b_path).unwrap();
        std::os::unix::fs::symlink("a", &c_path).unwrap();

        // Validation should not hang or panic
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("a"); // Points into circular chain

        // This should complete (not hang) and may succeed since we don't follow
        // chains
        let _result = SafeSymlink::validate(&link, &target, &dest, &config);
    }

    // Deep symlink nesting stress tests
    #[test]
    fn test_safe_symlink_deep_nesting_stress() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create deeply nested link
        let link = SafePath::validate(&PathBuf::from("a/b/c/d/e/f/g/h/i/j/link"), &dest, &config)
            .expect("link path should be valid");

        // Target that goes up and back down
        let target = PathBuf::from("../../../../../../../../../../x/y/z/file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "deep relative path staying internal should succeed"
        );
    }

    #[test]
    fn test_safe_symlink_excessive_parent_refs() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/link"), &dest, &config)
            .expect("link path should be valid");

        // More .. than depth can handle
        let target = PathBuf::from("../".repeat(50) + "file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SymlinkEscape { .. }));
    }

    // Test for symlink with banned target component
    #[test]
    fn test_safe_symlink_target_banned_component() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Target contains banned component
        let target = PathBuf::from(".git/config");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "symlink to banned component should be rejected"
        );
    }

    #[test]
    fn test_safe_symlink_self_reference() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Symlink to itself (link -> link)
        let target = PathBuf::from("link");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "self-referential symlink should be allowed (validation doesn't follow)"
        );
    }

    #[test]
    fn test_safe_symlink_empty_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Empty target
        let target = PathBuf::from("");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "empty symlink target should be rejected, not silently accepted"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_symlink_target_with_null_byte() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let target = PathBuf::from(OsStr::from_bytes(b"benign\0target"));

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "symlink target containing a null byte should be rejected"
        );
    }

    #[test]
    fn test_safe_symlink_current_dir_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("subdir/link"), &dest, &config)
            .expect("link path should be valid");

        // Target is current directory (.)
        let target = PathBuf::from(".");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok(), "current dir target should be allowed");
    }

    #[test]
    fn test_safe_symlink_parent_dir_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/link"), &dest, &config)
            .expect("link path should be valid");

        // Target is parent directory (..)
        let target = PathBuf::from("..");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok(), "parent dir target should be allowed");
    }

    #[test]
    fn test_safe_symlink_getters() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("mylink"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");

        // Test getters
        assert_eq!(symlink.link_path(), Path::new("mylink"));
        assert_eq!(symlink.target_path(), Path::new("target.txt"));
    }

    /// Two-hop symlink chain: the second symlink's target traverses through a
    /// symlink already written to disk, escaping the extraction root via
    /// on-disk resolution even though string-based normalization would
    /// pass.
    ///
    /// Attack chain (GHSA-83g3-92jg-28cx variant, issue #116):
    ///   Entry 1: dir   a/b/c/
    ///   Entry 2: link  a/b/c/up  ->  ../..   (resolves to a/ — safe, written)
    ///   Entry 3: link  a/b/escape -> c/up/../.. (string: a/b/ — PASS; disk:
    /// escapes dest)
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used)]
    fn test_safe_symlink_two_hop_chain_rejected() {
        use std::os::unix::fs;

        let (temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Set up the on-disk state that entry 2 would produce.
        let a = temp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        std::fs::create_dir_all(&c).unwrap();
        // a/b/c/up -> ../..  (resolves to a/)
        fs::symlink("../..", c.join("up")).unwrap();

        // Now validate entry 3: a/b/escape -> c/up/../..
        // String normalization gives a/b/ (within dest) — but on disk, c/up
        // resolves outside, so the chain escapes.
        let link = SafePath::validate(&PathBuf::from("a/b/escape"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("c/up/../..");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "two-hop symlink chain must be rejected"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_rejects_windows_hazards_in_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).expect("link");

        for target in ["dir/foo.", "dir/foo ", "dir/a:b", "sub/NUL"] {
            assert_matches!(
                SafeSymlink::validate(&link, &PathBuf::from(target), &dest, &config),
                Err(ArchiveError::SecurityViolation { .. }),
                "{target}"
            );
        }
    }

    mod parent_resolution {
        use super::*;
        use crate::security::fs_view::Node;
        use crate::security::fs_view::VirtualTree;

        const LINK: &str = "link";

        fn host_resolve(setup: impl FnOnce(&Path), start: &str, target: &str) -> Result<PathBuf> {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            setup(&root);
            resolve_through_symlinks_in(
                &root.join(start),
                Path::new(target),
                &root,
                Path::new(LINK),
                &HostFs,
            )
        }

        fn tree_resolve(
            setup: impl FnOnce(&mut VirtualTree),
            start: &str,
            target: &str,
        ) -> Result<PathBuf> {
            let root = Path::new("/dest");
            let mut tree = VirtualTree::new(root);
            setup(&mut tree);
            resolve_through_symlinks_in(
                &root.join(start),
                Path::new(target),
                root,
                Path::new(LINK),
                &tree,
            )
        }

        fn put(tree: &mut VirtualTree, path: &str, node: Node) {
            tree.insert(Path::new(path), node).expect("insert");
        }

        #[test]
        fn parent_dir_after_missing_component_is_rejected() {
            assert_matches!(
                host_resolve(|_| {}, "", "d/.."),
                Err(ArchiveError::SymlinkEscape { .. })
            );
            assert_matches!(
                tree_resolve(|_| {}, "", "d/.."),
                Err(ArchiveError::SymlinkEscape { .. })
            );
        }

        #[test]
        fn parent_dir_after_file_component_is_rejected() {
            assert_matches!(
                host_resolve(
                    |root| std::fs::write(root.join("f"), b"x").expect("file"),
                    "",
                    "f/.."
                ),
                Err(ArchiveError::SymlinkEscape { .. })
            );
            assert_matches!(
                tree_resolve(|t| put(t, "f", Node::File), "", "f/.."),
                Err(ArchiveError::SymlinkEscape { .. })
            );
        }

        #[test]
        fn parent_dir_after_existing_directory_is_resolved() {
            assert_matches!(
                host_resolve(
                    |root| std::fs::create_dir(root.join("d")).expect("dir"),
                    "",
                    "d/../x"
                ),
                Ok(_)
            );
            assert_matches!(
                tree_resolve(|t| put(t, "d", Node::Dir), "", "d/../x"),
                Ok(_)
            );
        }

        #[test]
        fn parent_dir_may_leave_own_missing_parent_directories() {
            assert_matches!(host_resolve(|_| {}, "sub", "../x"), Ok(_));
            assert_matches!(host_resolve(|_| {}, "a/b", "../../x"), Ok(_));
            assert_matches!(tree_resolve(|_| {}, "sub", "../x"), Ok(_));
            assert_matches!(
                tree_resolve(|_| {}, "sub", "../../x"),
                Err(ArchiveError::SymlinkEscape { .. })
            );
        }

        #[test]
        fn parent_dir_after_symlinked_directory_uses_resolved_location() {
            assert_matches!(
                tree_resolve(
                    |t| {
                        put(t, "p/q", Node::Dir);
                        put(t, "x", Node::Symlink(PathBuf::from("p/q")));
                    },
                    "",
                    "x/.."
                ),
                Ok(_)
            );
        }
    }
}
