//! Validated safe symlink type.

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::security::fs_view::LinkKind;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;
use super::SafePath;
use super::safe_path::ParentCheck;
use super::safe_path::Resolved;
use super::safe_path::check_component_for;
use crate::security::fs_view::Containment;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::LinkBase;
use crate::security::fs_view::ModelRoot as _;

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
/// use exarch_core::DestDir;
/// use exarch_core::SafePath;
/// use exarch_core::SafeSymlink;
/// use exarch_core::SecurityConfig;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.symlinks = exarch_core::Admit::Allow;
/// let config = config;
///
/// let link = SafePath::validate(&PathBuf::from("mylink"), &dest, &config)?;
/// let target = PathBuf::from("../target.txt");
///
/// let symlink = SafeSymlink::validate(&link, &target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSymlink<P: ParentCheck = Resolved> {
    link: SafePath<P>,
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
    /// # Destination handle
    ///
    /// On Unix and WASI the target is resolved handle-relatively from the
    /// destination, which this call opens by its path each time. An
    /// extraction validates against the descriptor it holds for its whole run
    /// instead, so a caller that extracts while the destination path may be
    /// replaced must use the extraction API rather than this function. On other
    /// platforms the target is resolved by path.
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
    /// use exarch_core::DestDir;
    /// use exarch_core::SafePath;
    /// use exarch_core::SafeSymlink;
    /// use exarch_core::SecurityConfig;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let mut config = SecurityConfig::default();
    /// config.allowed.symlinks = exarch_core::Admit::Allow;
    /// let config = config;
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
        config: &SecurityConfig,
    ) -> Result<Self> {
        Self::validate_in(link, target, dest, config, &HostFs)
    }
}

impl<P: ParentCheck> SafeSymlink<P> {
    /// Validates against `view` instead of the real filesystem.
    pub(crate) fn validate_in<V: FsView>(
        link: &SafePath<P>,
        target: &Path,
        root: &V::Root,
        config: &SecurityConfig,
        view: &V,
    ) -> Result<Self> {
        require_symlinks_allowed(config)?;

        // 1.5. Reject empty targets: an empty target does not point anywhere
        // (some platforms would silently create a dangling symlink); reject
        // it explicitly rather than letting it through.
        if target.is_empty() {
            return Err(Violation::LinkTargetEmpty(LinkKind::Symlink).into());
        }

        // 1.6. Reject null bytes in the target, matching the same check
        // already applied to the link path. Without this, a NUL byte falls
        // through to the OS and surfaces as a raw `io::Error` instead of a
        // structured `SecurityViolation`. The message intentionally omits
        // the raw target bytes so a NUL byte is never embedded in it.
        if super::safe_path::has_null_bytes(target) {
            return Err(Violation::LinkTargetNul(LinkKind::Symlink).into());
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
        if has_root_or_prefix(target) {
            return Err(ArchiveError::SymlinkEscape {
                path: link.as_path().to_path_buf(),
            });
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
                check_component_for(view.path_model(), comp, config)?;
                let comp_str = comp.to_string_lossy();
                if !config.is_path_component_allowed(&comp_str) {
                    return Err(Violation::LinkTargetBannedComponent {
                        component: comp_str.as_ref().into(),
                    }
                    .into());
                }
            }
        }

        // Validate target depth against max_path_depth
        if target_depth > config.max_path_depth.get() {
            return Err(Violation::SymlinkTargetDepth {
                depth: target_depth,
                max: config.max_path_depth.get(),
            }
            .into());
        }

        // 3-4. Verify the parent directory chain (not the link itself, which
        // extraction skips or replaces) contains no symlinks, and resolve the
        // target against the link's parent directory, following any on-disk
        // symlinks encountered during traversal.
        //
        // String-based normalization is insufficient: a target component that
        // is already a symlink written to disk by a previous entry can redirect
        // subsequent `..` traversal outside the extraction root (two-hop chain,
        // GHSA-83g3-92jg-28cx variant — issue #116).
        view.resolve_link_target(link.as_path(), target, LinkBase::LinkDirectory, root)?;

        Ok(Self {
            link: link.clone(),
            target_path: target.to_path_buf(),
        })
    }

    /// Returns the validated link path.
    #[inline]
    #[must_use]
    pub fn link(&self) -> &SafePath<P> {
        &self.link
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

    /// The target as a proof a sink can read: it came from a validated
    /// symlink.
    pub(crate) fn checked_target(&self) -> CheckedLinkTarget<'_> {
        CheckedLinkTarget(&self.target_path)
    }
}

/// The target of a symlink that passed validation, borrowed from its
/// [`SafeSymlink`].
///
/// Handed to an [`EntrySink`](crate::EntrySink) so it can tell a target the
/// pipeline checked (relative, free of banned components, resolving inside
/// the root) from any other path. Only a validated symlink can produce one:
/// the field is private and the sole constructor is crate-private. The path
/// is the target as the archive spells it, not resolved.
///
/// # Examples
///
/// ```
/// use exarch_core::CheckedLinkTarget;
///
/// fn stored_as_text(target: CheckedLinkTarget<'_>) -> String {
///     target.as_path().to_string_lossy().into_owned()
/// }
/// # let _ = stored_as_text;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedLinkTarget<'a>(&'a Path);

impl<'a> CheckedLinkTarget<'a> {
    /// The validated target, as the archive spells it.
    #[must_use]
    pub const fn as_path(&self) -> &'a Path {
        self.0
    }
}

/// Fails with the symlink-policy refusal unless `config` allows symlinks.
///
/// # Errors
///
/// Returns `SecurityViolation` ("symlinks not allowed") when symlinks are
/// disabled.
pub(crate) fn require_symlinks_allowed(config: &SecurityConfig) -> Result<()> {
    config
        .allowed
        .symlinks
        .is_allowed()
        .ok_or_else(|| Violation::LinksNotAllowed(LinkKind::Symlink).into())
}

/// Returns `true` when `target` contains a `Prefix` or `RootDir` component.
///
/// Such a target (drive, UNC, device namespace, or rooted path) is never
/// relative to the destination. Link validators call this before any
/// filesystem access so a hostile target such as `\\host\share\x` cannot
/// trigger a network or device probe on Windows
/// (GHSA-5qh5-c9fp-66jm class).
pub(crate) fn has_root_or_prefix(target: &Path) -> bool {
    target.components().any(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        )
    })
}

/// Verifies that no component in the parent directory chain of `path` is a
/// symlink. The leaf is not checked: extraction never follows it, it replaces
/// or skips whatever occupies it.
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
fn verify_parent_not_symlink<V: FsView>(path: &Path, dest: &Path, view: &V) -> Result<()> {
    let mut current = dest.to_path_buf();

    for component in path.parent().unwrap_or_else(|| Path::new("")).components() {
        current.push(component);

        match probe_is_symlink(view, &current, path)? {
            Some(true) => {
                return Err(ArchiveError::SymlinkEscape {
                    path: path.to_path_buf(),
                });
            }
            Some(false) => {}
            None => break,
        }
    }

    Ok(())
}

/// The path-keyed form of [`FsView::resolve_link_target`]: vets the parents of
/// `link` for [`LinkBase::LinkDirectory`], then resolves `target` through
/// `view`'s probes.
///
/// # Errors
///
/// See [`FsView::resolve_link_target`].
pub(crate) fn resolve_link_target_by_path<V: FsView>(
    view: &V,
    link: &Path,
    target: &Path,
    base: LinkBase,
    root: &V::Root,
) -> Result<PathBuf> {
    let dest = root.as_path();
    let start = match base {
        LinkBase::LinkDirectory => {
            verify_parent_not_symlink(link, dest, view)?;
            dest.join(link.parent().unwrap_or_else(|| Path::new("")))
        }
        LinkBase::Destination => dest.to_path_buf(),
    };
    resolve_through_symlinks_in(&start, target, root, link, view)
}

/// Asks `view` whether `path` is a symlink, failing closed.
///
/// `None` means nothing exists at `path` (missing, or below a file), so
/// nothing can lie below it either. A name past the host limit is the usual
/// name-too-long refusal; any other failure to inspect `path` refuses the link.
fn probe_is_symlink<V: FsView>(view: &V, path: &Path, link_path: &Path) -> Result<Option<bool>> {
    match view.is_symlink(path) {
        Ok(is_symlink) => Ok(Some(is_symlink)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidFilename => {
            Err(ArchiveError::Io(error))
        }
        Err(_) => Err(ArchiveError::SymlinkEscape {
            path: link_path.to_path_buf(),
        }),
    }
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
fn resolve_through_symlinks_in<V: FsView>(
    start: &Path,
    target: &Path,
    root: &V::Root,
    link_path: &Path,
    view: &V,
) -> Result<PathBuf> {
    let dest = root.as_path();
    let mut current = start.to_path_buf();

    for component in target.components() {
        match component {
            std::path::Component::ParentDir => {
                // If the current accumulated path is an on-disk symlink,
                // resolve it before applying `..` so the pop
                // operates on the real filesystem topology
                // rather than the string representation.
                if probe_is_symlink(view, &current, link_path)? == Some(true) {
                    current = canonical_within(view, &current, root, link_path)?;
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
                if probe_is_symlink(view, &current, link_path)? == Some(true) {
                    current = canonical_within(view, &current, root, link_path)?;
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

/// Canonicalizes `current` in `view`; a result outside `root`, or a failure to
/// resolve it, is a symlink escape.
///
/// A path the host cannot name at all (past its length limit) is not an escape:
/// it is the same name-too-long refusal every other length check reports.
fn canonical_within<V: FsView>(
    view: &V,
    current: &Path,
    root: &V::Root,
    link_path: &Path,
) -> Result<PathBuf> {
    match view.canonicalize(current, root) {
        Ok(Containment::Within(canonical)) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidFilename => {
            Err(ArchiveError::Io(error))
        }
        Ok(Containment::Escapes) | Err(_) => Err(ArchiveError::SymlinkEscape {
            path: link_path.to_path_buf(),
        }),
    }
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
    fn create_config_with_symlinks() -> SecurityConfig {
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;
        config
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
        assert_eq!(symlink.link().as_path(), Path::new("dir/link"));
        assert_eq!(symlink.target_path(), Path::new("../file.txt"));
    }

    #[test]
    #[cfg(unix)]
    fn a_target_through_a_link_past_the_host_path_limit_resolves_handle_relatively() {
        use crate::formats::dir_walker::DirWalker;
        use crate::formats::pinned_dir::PinnedRoot;
        use crate::security::fs_view::MAX_SYMLINK_TARGET_LEN;

        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();
        let chain = crate::test_utils::path_of_len(MAX_SYMLINK_TARGET_LEN);
        let root = PinnedRoot::open_for_test(dest.as_path()).expect("pin the destination");
        DirWalker::new(&config)
            .ensure_dir(&root, &SafePath::for_test(&chain))
            .expect("create the chain handle-relatively");
        std::os::unix::fs::symlink(&chain, dest.as_path().join("s")).expect("create the link");
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let result = SafeSymlink::validate(&link, Path::new("s/x"), &dest, &config);

        assert_matches!(result, Ok(_), "{result:?}");
    }

    #[test]
    fn test_safe_symlink_reject_when_disabled() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Refuse;

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
        assert_eq!(symlink.link().as_path(), Path::new("mylink"));
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

    /// Targets whose first component is a root or prefix on every platform.
    const ROOTED_TARGETS: [&str; 3] = ["/etc/passwd", "//host/share/x", "/"];

    #[test]
    fn test_has_root_or_prefix_flags_rooted_targets() {
        for target in ROOTED_TARGETS {
            assert!(has_root_or_prefix(Path::new(target)), "{target}");
        }
    }

    #[test]
    fn test_has_root_or_prefix_accepts_relative_targets() {
        for target in ["a", "a/b", "../a", "./a"] {
            assert!(!has_root_or_prefix(Path::new(target)), "{target}");
        }
    }

    #[test]
    fn test_safe_symlink_rejects_slash_unc_target_before_fs_access() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).expect("link");

        assert_matches!(
            SafeSymlink::validate(&link, Path::new("//host/share/x"), &dest, &config),
            Err(ArchiveError::SymlinkEscape { .. })
        );
    }

    /// Regression for GHSA-5qh5-c9fp-66jm: UNC and device-namespace targets
    /// must be rejected as escapes before any filesystem probe. Unverified
    /// locally; runs only in the Windows CI job.
    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_rejects_unc_and_device_targets_windows() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).expect("link");

        for target in [
            r"\\host\share\x",
            "//host/share/x",
            r"\\?\UNC\host\share\x",
            r"\\.\UNC\host\share\x",
            r"\??\UNC\host\share\x",
        ] {
            assert_matches!(
                SafeSymlink::validate(&link, &PathBuf::from(target), &dest, &config),
                Err(ArchiveError::SymlinkEscape { .. }),
                "{target}"
            );
        }
    }

    mod parent_resolution {
        use super::*;
        use crate::security::fs_view::Node;
        use crate::security::fs_view::VirtualRoot;
        use crate::security::fs_view::VirtualTree;

        const LINK: &str = "link";

        fn host_resolve(setup: impl FnOnce(&Path), start: &str, target: &str) -> Result<PathBuf> {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            setup(&root);
            resolve_through_symlinks_in(
                &root.join(start),
                Path::new(target),
                &DestDir::new(root.clone()).expect("dest"),
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
            let mut tree = VirtualTree::for_test(&VirtualRoot::at("/dest"));
            setup(&mut tree);
            resolve_through_symlinks_in(
                &root.join(start),
                Path::new(target),
                &VirtualRoot::at("/dest"),
                Path::new(LINK),
                &tree,
            )
        }

        fn put(tree: &mut VirtualTree, path: &str, node: Node) {
            tree.insert(Path::new(path), node).expect("insert");
        }

        #[cfg(unix)]
        #[test]
        fn host_hop_that_leaves_the_root_and_returns_is_an_escape() {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            std::os::unix::fs::symlink("..", root.join("a")).expect("symlink");
            let name = root.file_name().expect("name").to_string_lossy();
            for target in [
                format!("a/{name}/x"),
                format!("a/{name}/../x"),
                "a/..".into(),
            ] {
                assert_matches!(
                    resolve_through_symlinks_in(
                        &root,
                        Path::new(&target),
                        &DestDir::new(root.clone()).expect("dest"),
                        Path::new(LINK),
                        &HostFs,
                    ),
                    Err(ArchiveError::SymlinkEscape { .. }),
                    "{target}"
                );
            }
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
        fn a_target_below_a_file_resolves_the_same_in_both_views() {
            assert_matches!(
                host_resolve(
                    |root| std::fs::write(root.join("f"), b"x").expect("file"),
                    "",
                    "f/x"
                ),
                Ok(_)
            );
            assert_matches!(tree_resolve(|t| put(t, "f", Node::File), "", "f/x"), Ok(_));
        }

        #[test]
        fn a_parent_chain_through_a_file_is_not_a_symlink_refusal_in_both_views() {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            std::fs::write(root.join("f"), b"x").expect("file");
            assert_matches!(
                verify_parent_not_symlink(Path::new("f/g/l"), &root, &HostFs),
                Ok(())
            );

            let mut tree = VirtualTree::for_test(&VirtualRoot::at("/dest"));
            put(&mut tree, "f", Node::File);
            assert_matches!(
                verify_parent_not_symlink(Path::new("f/g/l"), Path::new("/dest"), &tree),
                Ok(())
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

    #[cfg(unix)]
    mod link_table {
        use super::*;
        use crate::formats::pinned_dir::PinnedRoot;
        use crate::security::fs_view::Node;
        use crate::security::fs_view::PinnedHostFs;
        use crate::security::fs_view::VirtualRoot;
        use crate::security::fs_view::VirtualTree;

        struct Case {
            name: &'static str,
            dirs: &'static [&'static str],
            files: &'static [&'static str],
            links: &'static [(&'static str, &'static str)],
            link: &'static str,
            target: &'static str,
            accepted: bool,
        }

        const fn case(
            name: &'static str,
            link: &'static str,
            target: &'static str,
            accepted: bool,
        ) -> Case {
            Case {
                name,
                dirs: &[],
                files: &[],
                links: &[],
                link,
                target,
                accepted,
            }
        }

        const CASES: &[Case] = &[
            case(
                "implicit parent, dotdot back into the root",
                "newdir/l",
                "../x",
                true,
            ),
            case(
                "implicit parents, dotdot past the root",
                "newdir/l",
                "../../x",
                false,
            ),
            case("dotdot past the root", "l", "../x", false),
            case("missing name then dotdot", "l", "d/..", false),
            Case {
                files: &["f"],
                ..case("below a file", "l", "f/x", true)
            },
            Case {
                files: &["f"],
                ..case("dotdot out of a file", "l", "f/..", false)
            },
            Case {
                dirs: &["d"],
                ..case("dotdot out of a directory", "l", "d/../x", true)
            },
            Case {
                dirs: &["d"],
                links: &[("s", "d")],
                ..case("through a link to a directory", "l", "s/x", true)
            },
            Case {
                dirs: &["d"],
                links: &[("s", "d")],
                ..case("dotdot out of a link to a directory", "l", "s/../x", true)
            },
            Case {
                links: &[("s", "missing")],
                ..case("through a dangling link", "l", "s/x", false)
            },
            Case {
                links: &[("s", "..")],
                ..case("through a link out of the root", "l", "s/x", false)
            },
            Case {
                dirs: &["d"],
                links: &[("s", "d")],
                ..case("parent that is a link", "s/l", "x", false)
            },
            Case {
                files: &["f"],
                ..case("parent chain below a file", "f/g/l", "x", true)
            },
            Case {
                dirs: &["a", "b"],
                links: &[("a/up", "../b")],
                ..case("link chain back into a sibling", "l", "a/up/x", true)
            },
        ];

        fn host_dest(case: &Case) -> (TempDir, DestDir) {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            for dir in case.dirs {
                std::fs::create_dir_all(root.join(dir)).expect("dir");
            }
            for file in case.files {
                std::fs::write(root.join(file), b"x").expect("file");
            }
            for (name, target) in case.links {
                std::os::unix::fs::symlink(target, root.join(name)).expect("link");
            }
            let dest = DestDir::new(root).expect("dest");
            (temp, dest)
        }

        fn tree_of(case: &Case) -> VirtualTree {
            let mut tree = VirtualTree::for_test(&VirtualRoot::at("/dest"));
            let mut put = |path: &str, node: Node| {
                tree.insert(Path::new(path), node).expect("insert");
            };
            for dir in case.dirs {
                put(dir, Node::Dir);
            }
            for file in case.files {
                put(file, Node::File);
            }
            for (name, target) in case.links {
                put(name, Node::Symlink(PathBuf::from(target)));
            }
            tree
        }

        fn verdict(result: &Result<PathBuf>, case: &Case, view: &str) {
            let accepted = result.is_ok();
            assert_eq!(
                accepted, case.accepted,
                "{} ({view}): {result:?}",
                case.name
            );
            if let Err(error) = result {
                assert_matches!(error, ArchiveError::SymlinkEscape { .. }, "{}", case.name);
            }
        }

        #[test]
        fn every_view_gives_the_same_verdict() {
            for case in CASES {
                let (link, target) = (Path::new(case.link), Path::new(case.target));
                let base = LinkBase::LinkDirectory;

                let (_temp, dest) = host_dest(case);
                verdict(
                    &resolve_link_target_by_path(&HostFs, link, target, base, &dest),
                    case,
                    "path",
                );
                verdict(
                    &HostFs.resolve_link_target(link, target, base, &dest),
                    case,
                    "handle",
                );
                let pinned = PinnedRoot::open_for_test(dest.as_path()).expect("pin");
                verdict(
                    &PinnedHostFs::new(&pinned).resolve_link_target(link, target, base, &dest),
                    case,
                    "pinned",
                );

                let root = VirtualRoot::at("/dest");
                verdict(
                    &tree_of(case).resolve_link_target(link, target, base, &root),
                    case,
                    "virtual",
                );
            }
        }

        #[test]
        fn a_hardlink_target_resolves_from_the_destination_in_every_view() {
            let case = Case {
                dirs: &["d"],
                links: &[("s", "d")],
                ..case("hardlink through a link", "x/h", "s/../d/f", true)
            };
            let (link, target) = (Path::new(case.link), Path::new(case.target));
            let base = LinkBase::Destination;
            let (_temp, dest) = host_dest(&case);
            verdict(
                &resolve_link_target_by_path(&HostFs, link, target, base, &dest),
                &case,
                "path",
            );
            verdict(
                &HostFs.resolve_link_target(link, target, base, &dest),
                &case,
                "handle",
            );
            let root = VirtualRoot::at("/dest");
            verdict(
                &tree_of(&case).resolve_link_target(link, target, base, &root),
                &case,
                "virtual",
            );
        }
    }

    mod failing_probes {
        use super::*;
        use crate::security::fs_view::Containment;
        use std::io::ErrorKind;

        /// Host view whose `is_symlink` fails with `kind` at one path.
        struct FailingProbe {
            at: PathBuf,
            kind: ErrorKind,
        }

        impl FsView for FailingProbe {
            type Root = DestDir;

            fn path_model(&self) -> crate::security::fs_view::PathModel {
                HostFs.path_model()
            }

            fn exists(&self, path: &Path) -> bool {
                HostFs.exists(path)
            }

            fn is_dir(&self, path: &Path) -> bool {
                HostFs.is_dir(path)
            }

            fn is_symlink(&self, path: &Path) -> std::io::Result<bool> {
                if path == self.at {
                    return Err(self.kind.into());
                }
                HostFs.is_symlink(path)
            }

            fn canonicalize(&self, path: &Path, root: &DestDir) -> std::io::Result<Containment> {
                HostFs.canonicalize(path, root)
            }
        }

        const LINK: &str = "link";

        fn fixture() -> (TempDir, PathBuf, DestDir) {
            let temp = TempDir::new().expect("tempdir");
            let root = temp.path().canonicalize().expect("canonical root");
            std::fs::create_dir_all(root.join("a/b/c")).expect("deep fixture");
            let dest = DestDir::new(root.clone()).expect("dest");
            (temp, root, dest)
        }

        fn resolve_with(kind: ErrorKind) -> Result<PathBuf> {
            let (_temp, root, dest) = fixture();
            let view = FailingProbe {
                at: root.join("a/b"),
                kind,
            };
            resolve_through_symlinks_in(&root, Path::new("a/b/c/x"), &dest, Path::new(LINK), &view)
        }

        fn verify_with(kind: ErrorKind) -> Result<()> {
            let (_temp, root, _dest) = fixture();
            let view = FailingProbe {
                at: root.join("a/b"),
                kind,
            };
            verify_parent_not_symlink(Path::new("a/b/c/l"), &root, &view)
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Verdict {
            Absent,
            Refused,
            TooLong,
        }

        fn verdict_of<T: std::fmt::Debug>(result: &Result<T>) -> Verdict {
            match result {
                Ok(_) => Verdict::Absent,
                Err(ArchiveError::SymlinkEscape { .. }) => Verdict::Refused,
                Err(ArchiveError::Io(e)) if e.kind() == ErrorKind::InvalidFilename => {
                    Verdict::TooLong
                }
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }

        #[test]
        fn a_probe_that_fails_is_judged_the_same_for_parents_and_targets() {
            const TABLE: &[(ErrorKind, Verdict)] = &[
                (ErrorKind::NotFound, Verdict::Absent),
                (ErrorKind::NotADirectory, Verdict::Absent),
                (ErrorKind::PermissionDenied, Verdict::Refused),
                (ErrorKind::Other, Verdict::Refused),
                (ErrorKind::InvalidFilename, Verdict::TooLong),
            ];
            for &(kind, expected) in TABLE {
                assert_eq!(
                    verdict_of(&resolve_with(kind)),
                    expected,
                    "target, {kind:?}"
                );
                assert_eq!(verdict_of(&verify_with(kind)), expected, "parent, {kind:?}");
            }
        }

        #[test]
        fn a_name_past_the_host_limit_is_judged_by_the_host_probe_itself() {
            let (_temp, root, dest) = fixture();
            let long = "a".repeat(300);
            assert_eq!(
                verdict_of(&verify_parent_not_symlink(
                    Path::new(&format!("{long}/l")),
                    &root,
                    &HostFs
                )),
                Verdict::TooLong
            );
            assert_eq!(
                verdict_of(&resolve_through_symlinks_in(
                    &root,
                    Path::new(&format!("{long}/x")),
                    &dest,
                    Path::new(LINK),
                    &HostFs
                )),
                Verdict::TooLong
            );
        }

        #[cfg(unix)]
        #[test]
        fn a_file_in_the_way_is_absence_for_host_and_model_alike() {
            use crate::security::fs_view::Node;
            use crate::security::fs_view::VirtualRoot;
            use crate::security::fs_view::VirtualTree;

            let (_temp, root, dest) = fixture();
            std::fs::write(root.join("f"), b"x").expect("file");
            let mut tree = VirtualTree::for_test(&VirtualRoot::at("/dest"));
            tree.insert(Path::new("f"), Node::File).expect("insert");
            let virtual_root = VirtualRoot::at("/dest");

            for (link, target) in [("f/l", "x"), ("f/g/l", "x"), ("l", "f/x"), ("l", "f/g/x")] {
                let host =
                    verify_parent_not_symlink(Path::new(link), &root, &HostFs).and_then(|()| {
                        resolve_through_symlinks_in(
                            &root,
                            Path::new(target),
                            &dest,
                            Path::new(link),
                            &HostFs,
                        )
                        .map(drop)
                    });
                let model = verify_parent_not_symlink(Path::new(link), Path::new("/dest"), &tree)
                    .and_then(|()| {
                        resolve_through_symlinks_in(
                            Path::new("/dest"),
                            Path::new(target),
                            &virtual_root,
                            Path::new(link),
                            &tree,
                        )
                        .map(drop)
                    });
                assert_eq!(verdict_of(&host), Verdict::Absent, "{link} -> {target}");
                assert_eq!(verdict_of(&model), Verdict::Absent, "{link} -> {target}");
            }
        }

        #[cfg(unix)]
        #[test]
        fn a_dangling_link_in_the_parent_chain_is_refused() {
            let (_temp, root, _dest) = fixture();
            std::os::unix::fs::symlink("missing", root.join("d")).expect("dangling link");
            assert_matches!(
                verify_parent_not_symlink(Path::new("d/l"), &root, &HostFs),
                Err(ArchiveError::SymlinkEscape { .. })
            );
        }
    }
}
