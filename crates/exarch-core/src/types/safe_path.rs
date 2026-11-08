//! Validated safe path type for archive extraction.

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::error::PortableHazard;
use crate::security::context::ValidationContext;
use crate::security::fs_view::Containment;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::ModelRoot as _;
use crate::security::fs_view::PathModel;
use crate::security::fs_view::blocked_parent_error;
use crate::security::fs_view::paths_start_with;
use crate::selection::Rewritten;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;
pub(crate) use super::parent_check::ParentCheck;
pub(crate) use super::parent_check::ParentVetting;
pub(crate) use super::parent_check::Resolved;
#[cfg(any(unix, target_os = "wasi"))]
pub(crate) use super::parent_check::Walked;

/// A validated path that is safe for extraction.
///
/// `SafePath` represents a path that has been validated to not contain:
/// - Path traversal attempts (`..`)
/// - Null bytes
/// - Absolute paths (unless explicitly allowed; leading root is stripped so
///   `dest.join()` always stays inside `dest`)
/// - Banned path components
/// - Excessive path depth
///
/// # Security Properties
///
/// - Can ONLY be constructed through validation
/// - NO `From<PathBuf>` implementation (security critical)
/// - Always resolves within the destination directory
/// - Normalized to remove redundant components (`.`, root prefix)
///
/// # Parent state
///
/// The type parameter records how the parent directory was vetted:
/// `Resolved` (the default) means
/// validation resolved it, so the path can be joined to the destination and
/// used by name. An extraction onto a pinned directory handle vets each
/// parent when it writes instead, and its paths cannot be joined by name.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::DestDir;
/// use exarch_core::SafePath;
/// use exarch_core::SecurityConfig;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default();
///
/// // Valid path
/// let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)?;
///
/// // Path traversal is rejected
/// let unsafe_path = PathBuf::from("../etc/passwd");
/// assert!(SafePath::validate(&unsafe_path, &dest, &config).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafePath<P: ParentCheck = Resolved>(PathBuf, PhantomData<fn() -> P>);

/// Reason carried by the violation raised for an empty entry name.
pub(crate) const EMPTY_PATH_REASON: &str = "empty path not allowed";

impl SafePath {
    /// Validates and constructs a `SafePath`.
    ///
    /// This is the ONLY public way to construct a `SafePath`. The validation
    /// process ensures the path is safe for extraction.
    ///
    /// # Performance
    ///
    /// **For non-existing paths**: ~300-500 ns (no I/O syscalls)
    /// **For existing paths**: ~5-50 us (involves `exists()` and
    /// `canonicalize()` syscalls)
    ///
    /// If validating many paths, consider batching or parallel validation.
    ///
    /// # Validation Steps
    ///
    /// 1. Check for null bytes in path
    /// 2. Reject absolute paths when `allow_absolute_paths = false`
    /// 3. Check for parent directory traversal (`..`)
    /// 4. Validate path depth does not exceed maximum
    /// 5. Check for banned path components; on Windows also reject reserved
    ///    device names (unless `allowed.windows_reserved_names`) and `:`
    /// 6. Normalize path components: strip root/prefix so `dest.join()` stays
    ///    inside `dest`; remove `.` (current-dir) components
    /// 7. Verify resolved path stays within destination directory
    ///
    /// When `allow_absolute_paths = true` the root component (`/` on Unix,
    /// drive prefix on Windows) is stripped here, making the path relative
    /// before `dest.join()` is applied. This is the centralized stripping
    /// point for TAR and 7z entries; ZIP names are pre-resolved by
    /// `resolve_zip_entry_path` before reaching this method.
    ///
    /// # Caller contract
    ///
    /// Callers MUST normalize `\` to `/` in entry names before constructing a
    /// `PathBuf` and passing it here. On Unix, `\` is a valid filename
    /// character, so `PathBuf::from("..\\..\\x")` yields a single component
    /// rather than three — defeating traversal detection. Use
    /// `formats::common::normalize_entry_name` for 7z (and any format that
    /// stores Windows-style paths) before calling `validate`.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation step fails:
    /// - `ArchiveError::PathTraversal` for `..`, bare root paths, or absolute
    ///   paths when the flag is not set
    /// - `ArchiveError::SecurityViolation` for banned components or excessive
    ///   depth
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::DestDir;
    /// use exarch_core::SafePath;
    /// use exarch_core::SecurityConfig;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let config = SecurityConfig::default();
    ///
    /// let safe = SafePath::validate(&PathBuf::from("valid/path.txt"), &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(path: &Path, dest: &DestDir, config: &SecurityConfig) -> Result<Self> {
        Self::validate_in(path, dest, config, &HostFs)
    }

    /// Validates `path` against `view` instead of the real filesystem.
    pub(crate) fn validate_in<V: FsView>(
        path: &Path,
        root: &V::Root,
        config: &SecurityConfig,
        view: &V,
    ) -> Result<Self> {
        let ctx = ValidationContext::<V>::new(config.allowed.symlinks.is_allowed());
        Self::validate_with_context_in(path, root, config, &ctx, view)
    }

    /// A `SafePath` over a literal, for tests that need no validation.
    #[cfg(test)]
    pub(crate) fn for_test(path: &str) -> Self {
        Self::new_unchecked(PathBuf::from(path))
    }

    /// Rebuilds a path the virtual tree assembled from names it stored from
    /// validated entries, re-checking its shape: only normal components, so it
    /// is relative, normalized and free of `..`.
    ///
    /// It carries no claim about depth or containment beyond what the stored
    /// names were validated for.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when a component is not a normal name.
    pub(crate) fn from_normalized(path: PathBuf) -> std::io::Result<Self> {
        if path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            Ok(Self::new_unchecked(path))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "landing path is not a normalized relative path",
            ))
        }
    }
}

impl<P: ParentCheck> SafePath<P> {
    /// Validates with optimization context that can skip `canonicalize()`.
    ///
    /// The parent directory is canonicalized unless it is the root itself. When
    /// symlinks are impossible (disabled in config AND none seen), the
    /// full-path `canonicalize()` is skipped.
    ///
    /// All other validation steps (null bytes, absolute paths, parent
    /// traversal, depth, banned components, prefix check) are always
    /// performed regardless of context.
    #[cfg(test)]
    pub(crate) fn validate_with_context(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig,
        ctx: &ValidationContext<'_, HostFs, P>,
    ) -> Result<Self> {
        Self::validate_with_context_in(path, dest, config, ctx, &HostFs)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one cohesive sequence; splitting it would obscure the order of checks"
    )]
    pub(crate) fn validate_with_context_in<V: FsView>(
        path: &Path,
        root: &V::Root,
        config: &SecurityConfig,
        ctx: &ValidationContext<'_, V, P>,
        view: &V,
    ) -> Result<Self> {
        let dest = root.as_path();
        // Reject empty paths explicitly
        if path.is_empty() {
            return Err(Violation::EmptyPath.into());
        }

        // Archive root entries ("." or "./") represent the extraction directory
        // itself. They are produced by `tar -C /dir .` and are always safe.
        // Return immediately — no further validation needed.
        if path == Path::new(".") || path == Path::new("./") {
            return Ok(Self::new_unchecked(PathBuf::new()));
        }

        // 1. Check for null bytes
        if has_null_bytes(path) {
            return Err(Violation::NulInPath {
                path: path.display().to_string().into(),
            }
            .into());
        }

        // 2. Check for absolute paths
        if path.is_absolute() && !config.allowed.absolute_paths.is_allowed() {
            return Err(ArchiveError::PathTraversal {
                path: path.to_path_buf(),
            });
        }

        // Single-pass validation and normalization
        let mut depth = 0;
        let mut normalized = PathBuf::new();
        let mut needs_normalization = false;
        let has_banned_components = !config.banned_path_components.is_empty();

        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(ArchiveError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
                Component::Normal(comp) => {
                    depth += 1;

                    check_component_for(view.path_model(), comp, config)?;

                    if has_banned_components {
                        let comp_str = comp
                            .to_str()
                            .map_or_else(|| comp.to_string_lossy(), Cow::Borrowed);

                        if !config.is_path_component_allowed(&comp_str) {
                            return Err(Violation::BannedComponent {
                                component: comp_str.as_ref().into(),
                            }
                            .into());
                        }
                    }

                    normalized.push(component);
                }
                Component::CurDir => {
                    needs_normalization = true;
                }
                Component::RootDir | Component::Prefix(_) => {
                    if !config.allowed.absolute_paths.is_allowed() {
                        return Err(ArchiveError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                    // Strip root/prefix so final_path stays relative;
                    // dest.join() would otherwise discard
                    // dest entirely for absolute paths.
                    // This is the canonical stripping point — format handlers
                    // (tar, sevenz) pass raw entry names straight through.
                    // ZIP is the exception: names are pre-resolved in
                    // resolve_zip_entry_path.
                    needs_normalization = true;
                }
            }
        }

        // Bare absolute paths like `/` or `C:\` produce an empty normalized
        // path after stripping the root/prefix component. Reject them.
        if needs_normalization && normalized.is_empty() && depth == 0 {
            return Err(ArchiveError::PathTraversal {
                path: path.to_path_buf(),
            });
        }

        // Check path depth
        if depth > config.max_path_depth.get() {
            return Err(Violation::PathDepth {
                depth,
                max: config.max_path_depth.get(),
            }
            .into());
        }

        let final_path = if needs_normalization {
            Cow::Owned(normalized)
        } else {
            Cow::Borrowed(path)
        };

        // Verify resolved path stays within destination
        let resolved = dest.join(final_path.as_ref());

        // The root is already canonical, so a direct child needs no parent
        // probe; a walker-backed target vets the parent at write time instead.
        if let Some(parent) = resolved
            .parent()
            .filter(|parent| *parent != dest && matches!(P::VETTING, ParentVetting::Validator))
        {
            match view.canonicalize(parent, root) {
                Ok(Containment::Within(_)) => {}
                Ok(Containment::Escapes) => {
                    return Err(ArchiveError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(
                        blocked_parent_error(view, root, &final_path).unwrap_or_else(|| {
                            ArchiveError::Io(std::io::Error::new(
                                e.kind(),
                                crate::IoContext::new(
                                    "failed to canonicalize parent",
                                    e.to_string(),
                                ),
                            ))
                        }),
                    );
                }
            }
        }

        // Full path canonicalization: skip when symlinks are impossible
        if ctx.needs_full_canonicalize() {
            match view.canonicalize(&resolved, root) {
                Ok(Containment::Within(_)) => {}
                Ok(Containment::Escapes) => {
                    return Err(ArchiveError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound || defers_to_walker::<P>(&e) => {
                    if !paths_start_with(&resolved, dest) {
                        return Err(ArchiveError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) => {
                    return Err(
                        blocked_parent_error(view, root, &final_path).unwrap_or_else(|| {
                            ArchiveError::Io(std::io::Error::new(
                                e.kind(),
                                crate::IoContext::new("failed to canonicalize path", e.to_string()),
                            ))
                        }),
                    );
                }
            }
        } else {
            // Symlinks impossible -- prefix check is still mandatory
            if !paths_start_with(&resolved, dest) {
                return Err(ArchiveError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
        }

        Ok(Self::new_unchecked(final_path.into_owned()))
    }

    /// Validates a path a selection rewrite produced as a landing.
    ///
    /// The one way a [`Rewritten`] becomes a `SafePath`, with every check an
    /// archive name gets.
    ///
    /// # Errors
    ///
    /// Returns the validation error of the rewritten name.
    pub(crate) fn validate_rewritten_in<V: FsView>(
        rewritten: &Rewritten,
        root: &V::Root,
        config: &SecurityConfig,
        ctx: &ValidationContext<'_, V, P>,
        view: &V,
    ) -> Result<Self> {
        Self::validate_with_context_in(rewritten.as_path(), root, config, ctx, view)
    }

    /// The result of this module's own validation; no other module builds a
    /// `SafePath` without it.
    const fn new_unchecked(path: PathBuf) -> Self {
        Self(path, PhantomData)
    }

    /// Returns the path as a `&Path`.
    #[inline]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Converts into the inner `PathBuf`.
    #[inline]
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// Whether a canonicalize failure is a name the host cannot resolve by path
/// (past its length limit, or invalid on Windows) that the walker's
/// handle-relative walk decides instead.
fn defers_to_walker<P: ParentCheck>(err: &std::io::Error) -> bool {
    P::VETTING == ParentVetting::Walker && err.kind() == std::io::ErrorKind::InvalidFilename
}

/// Why a path component is hazardous on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsComponentHazard {
    /// Legacy device name such as `NUL` or `COM1`; may be allowed by config.
    ReservedDeviceName,
    /// `:` introduces an NTFS alternate data stream; never allowed.
    StreamSeparator,
    /// Windows strips trailing dots and spaces, aliasing another name; never
    /// allowed.
    TrailingDotOrSpace,
}

/// Classifies `comp` against the hazards that [`PathModel::Portable`] adds to
/// the Windows ones. Pure and platform-independent.
pub(crate) fn portable_component_hazard(comp: &OsStr) -> Option<PortableHazard> {
    let Some(text) = comp.to_str() else {
        return Some(PortableHazard::NotUtf8);
    };
    if text.contains('\\') {
        Some(PortableHazard::Backslash)
    } else if text
        .contains(|c: char| matches!(c, '<' | '>' | '"' | '|' | '?' | '*') || c <= '\u{1f}')
    {
        Some(PortableHazard::ForbiddenCharacter)
    } else {
        None
    }
}

/// Rejects the component hazards of `model`: none for the host's own rules
/// except on Windows, and the strictest set for [`PathModel::Portable`].
pub(crate) fn check_component_for(
    model: PathModel,
    comp: &OsStr,
    config: &SecurityConfig,
) -> Result<()> {
    let host = if cfg!(windows) {
        HostOs::Windows
    } else {
        HostOs::Other
    };
    check_component_on(model, host, comp, config)
}

/// The platform whose component rules a [`PathModel::Host`] check applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostOs {
    Windows,
    Other,
}

/// [`check_component_for`] with the host platform made explicit, so the
/// Windows behaviour is testable everywhere.
pub(crate) fn check_component_on(
    model: PathModel,
    host: HostOs,
    comp: &OsStr,
    config: &SecurityConfig,
) -> Result<()> {
    if model == PathModel::Host && host == HostOs::Other {
        return Ok(());
    }
    if let Some(hazard) = portable_component_hazard(comp) {
        return Err(Violation::UnsafeComponent {
            hazard,
            model,
            component: escaped_component(comp).into(),
        }
        .into());
    }
    check_windows_component(comp, config)
}

/// Spells `comp` injectively ([`path_text`](fn@crate::path_text)) with control
/// characters escaped, for error messages.
fn escaped_component(comp: &OsStr) -> String {
    let mut out = String::new();
    for ch in crate::path_text(std::path::Path::new(comp)).chars() {
        if ch == '\\' {
            out.push(ch);
        } else {
            out.extend(ch.escape_debug());
        }
    }
    out
}

/// Classifies `comp`, reporting never-allowed hazards before the
/// configurable reserved-name one. Pure and platform-independent.
pub(crate) fn windows_component_hazard(comp: &OsStr) -> Option<WindowsComponentHazard> {
    let lossy = comp.to_string_lossy();
    if lossy.contains(':') {
        Some(WindowsComponentHazard::StreamSeparator)
    } else if lossy.ends_with(['.', ' ']) {
        Some(WindowsComponentHazard::TrailingDotOrSpace)
    } else if is_windows_reserved_component(comp) {
        Some(WindowsComponentHazard::ReservedDeviceName)
    } else {
        None
    }
}

/// Rejects Windows-specific hazardous components (see
/// [`WindowsComponentHazard`]).
pub(crate) fn check_windows_component(comp: &OsStr, config: &SecurityConfig) -> Result<()> {
    match windows_component_hazard(comp) {
        None => Ok(()),
        Some(WindowsComponentHazard::ReservedDeviceName)
            if config.allowed.windows_reserved_names.is_allowed() =>
        {
            Ok(())
        }
        Some(WindowsComponentHazard::ReservedDeviceName) => Err(Violation::ReservedDeviceName {
            component: escaped_component(comp).into(),
        }
        .into()),
        Some(WindowsComponentHazard::StreamSeparator) => {
            Err(stream_separator_error(&escaped_component(comp)))
        }
        Some(WindowsComponentHazard::TrailingDotOrSpace) => Err(Violation::TrailingDotOrSpace {
            component: escaped_component(comp).into(),
        }
        .into()),
    }
}

/// The error for a path component containing `:`, which Windows treats as a
/// drive or alternate-data-stream separator.
pub(crate) fn stream_separator_error(comp: &str) -> ArchiveError {
    Violation::StreamSeparator {
        component: comp.into(),
    }
    .into()
}

/// Returns `true` if `comp` names a Windows legacy device.
///
/// The name is the text before the first `.`, with trailing spaces trimmed,
/// compared ASCII case-insensitively against `CON`, `PRN`, `AUX`, `NUL`,
/// `COM0`-`COM9`, `LPT0`-`LPT9`, the superscript forms `COM¹²³⁴⁵⁶⁷⁸⁹` /
/// `LPT¹²³⁴⁵⁶⁷⁸⁹`, `CONIN$`, `CONOUT$`, `CLOCK$` and `CONFIG$`. Pure and
/// platform-independent; callers decide whether to apply it.
///
/// The list is a superset of zip2 9.4.1 and 9.4.2. Microsoft documents only the
/// superscripts `¹²³`; the device status of `CLOCK$`, `CONFIG$` and `⁴`-`⁹` is
/// unverified on a Windows host. They are refused fail-closed because accepting
/// a real device name is the dangerous failure mode.
///
/// # Examples
///
/// ```
/// use exarch_core::is_windows_reserved_component;
/// use std::ffi::OsStr;
///
/// assert!(is_windows_reserved_component(OsStr::new("NUL.tar.gz")));
/// assert!(!is_windows_reserved_component(OsStr::new("console.txt")));
/// ```
#[must_use]
#[cfg_attr(not(feature = "testing"), allow(unreachable_pub))]
pub fn is_windows_reserved_component(comp: &OsStr) -> bool {
    const PLAIN: [&str; 8] = [
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "CONFIG$",
    ];
    let lossy = comp.to_string_lossy();
    let base = lossy
        .split_once('.')
        .map_or(&*lossy, |(base, _)| base)
        .trim_end_matches(' ');

    if PLAIN.iter().any(|n| base.eq_ignore_ascii_case(n)) {
        return true;
    }

    let Some(prefix) = base.get(..3) else {
        return false;
    };
    if !(prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT")) {
        return false;
    }
    let mut rest = base[3..].chars();
    matches!(
        (rest.next(), rest.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}' | '\u{2074}'..='\u{2079}'), None)
    )
}

/// Checks if a path contains null bytes.
#[cfg(unix)]
pub(crate) fn has_null_bytes(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().contains(&b'\0')
}

/// Checks if a path contains null bytes.
#[cfg(not(unix))]
pub(crate) fn has_null_bytes(path: &Path) -> bool {
    path.to_str().is_none_or(|s| s.contains('\0'))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::items_after_statements
)]
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

    #[test]
    fn from_normalized_accepts_only_normal_components() {
        for ok in ["", "a", "a/b/c.txt"] {
            assert!(SafePath::from_normalized(PathBuf::from(ok)).is_ok(), "{ok}");
        }
        for bad in ["/a", "../a", "a/../b", "./a"] {
            assert!(
                SafePath::from_normalized(PathBuf::from(bad)).is_err(),
                "{bad}"
            );
        }
    }

    // Empty path handling test (MED-004)
    #[test]
    fn test_empty_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let result = SafePath::validate(&PathBuf::from(""), &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "empty path should be explicitly rejected (MED-004)"
        );
    }

    #[test]
    fn test_safe_path_valid_relative() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("foo/bar/baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), path.as_path());
    }

    #[test]
    fn test_safe_path_reject_parent_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("../etc/passwd"),
            PathBuf::from("foo/../../etc/passwd"),
            PathBuf::from("foo/../../../etc/passwd"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert_matches!(
                result,
                Err(ArchiveError::PathTraversal { .. }),
                "path should be rejected: {}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_path_reject_absolute_unix() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("/etc/passwd");
        let result = SafePath::validate(&path, &dest, &config);
        assert_matches!(result, Err(ArchiveError::PathTraversal { .. }));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_reject_absolute_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("\\\\server\\share\\file"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert_matches!(result, Err(ArchiveError::PathTraversal { .. }));
        }
    }

    #[test]
    fn test_safe_path_allow_absolute_when_configured() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.absolute_paths = crate::Admit::Allow;

        // Verify that an external absolute path is stripped to a relative path
        // so dest.join() resolves inside dest, not at the original absolute
        // location.
        let result = SafePath::validate(Path::new("/some/external/path"), &dest, &config);
        assert!(
            result.is_ok(),
            "absolute path with flag should succeed: {result:?}"
        );
        let safe = result.expect("safe");
        assert_eq!(safe.as_path(), Path::new("some/external/path"));
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_path_bare_slash_rejected_when_absolute_allowed() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.absolute_paths = crate::Admit::Allow;

        let result = SafePath::validate(Path::new("/"), &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "bare '/' must be rejected as PathTraversal even with allow_absolute_paths"
        );
    }

    #[test]
    fn test_safe_path_reject_excessive_depth() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.max_path_depth = crate::non_zero!(3);

        // 4 components - should be rejected
        let path = PathBuf::from("a/b/c/d");
        let result = SafePath::validate(&path, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));

        // 3 components - should be allowed
        let path = PathBuf::from("a/b/c");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_path_reject_banned_components() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("project/.git/config"),
            PathBuf::from("user/.ssh/id_rsa"),
            PathBuf::from(".gnupg/private-keys"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert_matches!(
                result,
                Err(ArchiveError::SecurityViolation { .. }),
                "path should be rejected: {}",
                path.display()
            );
        }
    }

    #[test]
    fn test_safe_path_normalize_dot_components() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("foo/./bar/./baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));
    }

    #[test]
    fn test_safe_path_null_bytes() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let bytes = b"file\0.txt";
            let os_str = OsStr::from_bytes(bytes);
            let path = PathBuf::from(os_str);

            let result = SafePath::validate(&path, &dest, &config);
            assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
        }

        #[cfg(windows)]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;

            // Windows test for null bytes
            let wide: Vec<u16> = "file\0.txt".encode_utf16().collect();
            let os_string = OsString::from_wide(&wide);
            let path = PathBuf::from(os_string);

            let result = SafePath::validate(&path, &dest, &config);
            assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
        }
    }

    #[test]
    fn test_has_null_bytes() {
        let normal = PathBuf::from("normal/path.txt");
        assert!(!has_null_bytes(&normal));

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let bytes = b"file\0.txt";
            let os_str = OsStr::from_bytes(bytes);
            let with_null = PathBuf::from(os_str);
            assert!(has_null_bytes(&with_null));
        }
    }

    #[test]
    fn test_normalize_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Normalization now happens in single-pass validation
        // Path with . components should be normalized
        let path = PathBuf::from("foo/./bar/./baz.txt");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));

        let path = PathBuf::from("./foo/bar");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar"));

        // Path without . components should remain unchanged
        let path = PathBuf::from("foo/bar/baz.txt");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));
    }

    #[test]
    fn test_safe_path_equality() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let safe1 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let safe2 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");

        assert_eq!(safe1, safe2);
    }

    #[test]
    fn test_safe_path_clone() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let cloned = safe.clone();

        assert_eq!(safe, cloned);
    }

    // Test for empty path (MED-004)
    #[test]
    fn test_safe_path_empty() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("");
        let result = SafePath::validate(&path, &dest, &config);

        // Empty paths are now explicitly rejected
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "empty path should be explicitly rejected"
        );
    }

    // Path length boundary tests
    #[test]
    fn test_safe_path_at_max_depth() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.max_path_depth = crate::non_zero!(5);

        // Exactly at limit
        let path = PathBuf::from("a/b/c/d/e");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        // One over limit
        let path = PathBuf::from("a/b/c/d/e/f");
        let result = SafePath::validate(&path, &dest, &config);
        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
    }

    // Single component path test
    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_safe_path_single_component() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.unwrap();
        assert_eq!(safe.as_path(), Path::new("file.txt"));
    }

    // Unicode edge case tests
    #[test]
    fn test_safe_path_unicode() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Emoji in path
        let path = PathBuf::from("folder/\u{1f4c1}test.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        // Unicode normalization forms could differ
        let path = PathBuf::from("caf\u{e9}");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_windows_component_rejects_reserved_and_colon_by_default() {
        let config = SecurityConfig::default();
        for name in [
            "NUL.tar.gz",
            "CON ",
            "con.",
            "CON",
            "Aux.txt",
            "COM\u{b9}",
            "LPT\u{b3}.log",
            "CONIN$",
            "conout$",
            "a:b",
            "file.txt:stream",
        ] {
            assert_matches!(
                check_windows_component(OsStr::new(name), &config),
                Err(ArchiveError::SecurityViolation { .. }),
                "{name}"
            );
        }
        for name in ["console", "COM10", "file.txt", "xCON", "a.b.c"] {
            assert!(
                check_windows_component(OsStr::new(name), &config).is_ok(),
                "{name}"
            );
        }
    }

    #[test]
    fn test_check_windows_component_opt_out_allows_reserved_but_never_colon() {
        let config = SecurityConfig::default().with_allow_windows_reserved_names(true);

        assert!(check_windows_component(OsStr::new("NUL.tar.gz"), &config).is_ok());
        assert!(check_windows_component(OsStr::new("CONIN$"), &config).is_ok());
        assert_matches!(
            check_windows_component(OsStr::new("a:b"), &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    fn test_check_windows_component_permissive_preset_still_rejects() {
        let config = SecurityConfig::permissive();

        assert_matches!(
            check_windows_component(OsStr::new("CON"), &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    fn windows_hazard_classifier_orders_never_allowed_first() {
        use WindowsComponentHazard::*;
        let cases: [(&str, Option<WindowsComponentHazard>); 11] = [
            ("file.txt", None),
            ("a:b", Some(StreamSeparator)),
            ("foo.", Some(TrailingDotOrSpace)),
            ("foo ", Some(TrailingDotOrSpace)),
            ("...", Some(TrailingDotOrSpace)),
            ("NUL", Some(ReservedDeviceName)),
            ("NUL.tar.gz", Some(ReservedDeviceName)),
            ("NUL.", Some(TrailingDotOrSpace)),
            ("NUL :x", Some(StreamSeparator)),
            (".hidden", None),
            ("a.b", None),
        ];
        for (name, expected) in cases {
            assert_eq!(
                windows_component_hazard(OsStr::new(name)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn check_windows_component_rejects_trailing_dot_even_with_reserved_opt_out() {
        let config = SecurityConfig::default().with_allow_windows_reserved_names(true);
        for name in ["foo.", "foo ", "NUL."] {
            assert_matches!(
                check_windows_component(OsStr::new(name), &config),
                Err(ArchiveError::SecurityViolation { .. }),
                "{name}"
            );
        }
        assert!(check_windows_component(OsStr::new("NUL"), &config).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_trailing_dot_and_space_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        for name in ["dir/foo.", "dir/foo ", "bar./x"] {
            assert_matches!(
                SafePath::validate(Path::new(name), &dest, &config),
                Err(ArchiveError::SecurityViolation { .. }),
                "{name}"
            );
        }
    }

    #[test]
    fn validate_in_rejects_parent_chain_resolving_outside_tree_root() {
        use crate::security::fs_view::Node;
        use crate::security::fs_view::VirtualRoot;
        use crate::security::fs_view::VirtualTree;

        let dest = VirtualRoot::new();
        let config = SecurityConfig::default().with_allow_symlinks(true);
        let mut tree = VirtualTree::for_test(&dest);
        tree.insert(Path::new("up"), Node::Symlink(PathBuf::from("..")))
            .expect("insert");

        assert_matches!(
            SafePath::validate_in(Path::new("up/f"), &dest, &config, &tree),
            Err(ArchiveError::PathTraversal { .. })
        );
        assert!(SafePath::validate_in(Path::new("ok/f"), &dest, &config, &tree).is_ok());
    }

    #[test]
    fn test_is_windows_reserved_component() {
        for name in [
            "CON",
            "con",
            "Prn",
            "AUX",
            "nul",
            "COM0",
            "com1",
            "COM9",
            "LPT0",
            "lpt9",
            "COM\u{b9}",
            "COM\u{b2}",
            "LPT\u{b3}",
            "CONIN$",
            "conout$",
            "CLOCK$",
            "clock$.txt",
            "Config$",
            "COM\u{2074}",
            "COM\u{2079}",
            "lpt\u{2077}",
            "CON.txt",
            "NUL.tar.gz",
            "aux.",
            "CON ",
            "nul .txt",
        ] {
            assert!(is_windows_reserved_component(OsStr::new(name)), "{name}");
        }
        for name in [
            "console",
            "CONS",
            "COM",
            "COM10",
            "COM1x",
            "LPT",
            "COMA",
            "CON1",
            "xCON",
            "file.CON",
            ".CON",
            "",
            "\u{e9}\u{e9}",
            "CLOCK",
            "CONFIG",
            "CLOCK$$",
            "COM\u{2073}",
            "COM\u{207a}",
            "COM\u{2074}\u{2074}",
        ] {
            assert!(!is_windows_reserved_component(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_reserved_names_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let permissive = SecurityConfig::permissive();

        for name in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"] {
            let path = PathBuf::from(format!("folder/{name}.txt"));
            for cfg in [&config, &permissive] {
                assert_matches!(
                    SafePath::validate(&path, &dest, cfg),
                    Err(ArchiveError::SecurityViolation { .. })
                );
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_reserved_names_opt_out() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().with_allow_windows_reserved_names(true);

        assert!(SafePath::validate(Path::new("folder/CON.txt"), &dest, &config).is_ok());
        assert_matches!(
            SafePath::validate(Path::new("folder/a:stream"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_colon_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        assert_matches!(
            SafePath::validate(Path::new("file.txt:stream"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn test_safe_path_reserved_names_accepted_off_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        assert!(SafePath::validate(Path::new("folder/CON.txt"), &dest, &config).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_parent_chain() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create: dest/parent_dir -> /tmp (symlink to outside)
        let parent_symlink = temp.path().join("parent_dir");
        symlink("/tmp", &parent_symlink).expect("failed to create symlink");

        // Try to create path through symlinked parent
        let malicious_path = PathBuf::from("parent_dir/evil.txt");

        let result = SafePath::validate(&malicious_path, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink in parent chain should be detected and rejected"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_middle_of_path() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create legitimate directory
        let legit_dir = temp.path().join("legit");
        std::fs::create_dir(&legit_dir).expect("failed to create dir");

        // Create symlink within that directory pointing outside
        let symlink_path = legit_dir.join("escape");
        symlink("/etc", &symlink_path).expect("failed to create symlink");

        // Try to access through the symlink
        let malicious_path = PathBuf::from("legit/escape/passwd");

        let result = SafePath::validate(&malicious_path, &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink in middle of path should be detected"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_legitimate_file_in_real_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create real directory (not symlink)
        let real_dir = temp.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("failed to create dir");

        // Path through real directory should work
        let safe_path = PathBuf::from("real_dir/file.txt");

        let result = SafePath::validate(&safe_path, &dest, &config);
        assert!(result.is_ok(), "path through real directory should succeed");
    }

    // --- Tests for validate_with_context optimization ---

    #[test]
    fn test_validate_with_context_missing_parent_still_validates() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let ctx = ValidationContext::new(false);

        // Path whose parent doesn't exist
        let path = PathBuf::from("unknown_dir/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        // Should succeed since parent doesn't exist (NotFound is OK)
        assert!(
            result.is_ok(),
            "non-existent parent should be OK: {result:?}"
        );
    }

    #[test]
    fn test_validate_with_context_symlink_free_fast_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default(); // symlinks = false

        // No symlinks -> fast path (no full canonicalize)
        let ctx = ValidationContext::new(false);
        let path = PathBuf::from("some/path/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "symlink-free fast path should work");
    }

    #[test]
    fn test_validate_with_context_symlink_seen_disables_fast_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let mut ctx = ValidationContext::new(false);
        ctx.mark_symlink_seen();

        // After marking symlink seen, needs_full_canonicalize returns true
        assert!(ctx.needs_full_canonicalize());

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_with_context_still_catches_symlink_attack() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create a symlink pointing outside dest
        let malicious_link = temp.path().join("evil_dir");
        symlink("/tmp", &malicious_link).expect("failed to create symlink");

        let ctx = ValidationContext::new(false);

        let path = PathBuf::from("evil_dir/payload.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink attack must be caught even with context: {result:?}"
        );
    }

    // --- Additional tests for canonicalization optimization edge cases ---

    #[test]
    #[cfg(unix)]
    fn test_preexisting_symlink_in_subdir_is_caught() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let sub_dir = dest.as_path().join("subdir");
        std::fs::create_dir(&sub_dir).expect("should create dir");

        // Create a symlink INSIDE that directory pointing outside
        let evil_link = sub_dir.join("escape");
        symlink("/tmp", &evil_link).expect("failed to create symlink");

        // The parent canonicalization layer catches the symlink escape
        // regardless of the symlink-free fast path.
        let ctx = ValidationContext::new(false);
        let path = PathBuf::from("subdir/escape/payload.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "parent canonicalization must catch symlink even in fast path: {result:?}"
        );

        // With symlink_seen marked, both parent AND full canonicalize run
        let mut ctx_with_symlink = ValidationContext::new(false);
        ctx_with_symlink.mark_symlink_seen();
        let result_with_symlink =
            SafePath::validate_with_context(&path, &dest, &config, &ctx_with_symlink);
        assert_matches!(
            result_with_symlink,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink attack must also be caught with symlink_seen=true: {result_with_symlink:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_as_direct_child_is_a_file_name() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let sub_dir = dest.as_path().join("trusted");
        std::fs::create_dir(&sub_dir).expect("should create dir");

        // Create symlink as a direct child: trusted/link -> /tmp
        let link = sub_dir.join("link");
        symlink("/tmp", &link).expect("failed to create symlink");

        // The symlink-free fast path only does a prefix check on the
        // un-resolved path, which passes: the entry names a direct child, not
        // a traversal through a symlink directory. Writing through the link
        // itself is refused by the O_NOFOLLOW open.
        let ctx = ValidationContext::new(false);
        let path = PathBuf::from("trusted/link");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "direct child is a file name, not traversal: {result:?}"
        );
    }

    #[test]
    fn test_validate_backward_compat_same_result() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let test_paths = vec![
            PathBuf::from("file.txt"),
            PathBuf::from("dir/file.txt"),
            PathBuf::from("a/b/c/file.txt"),
            PathBuf::from("./normalized.txt"),
        ];

        for path in &test_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks.is_allowed());
            let result_with_ctx = SafePath::validate_with_context(path, &dest, &config, &ctx);

            assert_eq!(
                result_validate.is_ok(),
                result_with_ctx.is_ok(),
                "validate and validate_with_context should agree for path: {}",
                path.display()
            );

            if let (Ok(a), Ok(b)) = (&result_validate, &result_with_ctx) {
                assert_eq!(
                    a.as_path(),
                    b.as_path(),
                    "validate and validate_with_context should produce same SafePath"
                );
            }
        }
    }

    #[test]
    fn test_validate_backward_compat_error_paths() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let error_paths = vec![
            PathBuf::from("../escape"),
            PathBuf::from(""),
            PathBuf::from("project/.git/config"),
        ];

        for path in &error_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks.is_allowed());
            let result_with_ctx = SafePath::validate_with_context(path, &dest, &config, &ctx);

            assert!(
                result_validate.is_err() && result_with_ctx.is_err(),
                "both should reject path: {}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_with_context_symlinks_allowed_catches_escape() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let sub = dest.as_path().join("safe_dir");
        std::fs::create_dir(&sub).expect("should create dir");

        // Create symlink pointing outside in another location
        let evil = dest.as_path().join("evil");
        symlink("/tmp", &evil).expect("failed to create symlink");

        // With symlinks_allowed=true: needs_full_canonicalize is true,
        // so the full canonicalize runs and catches the symlink
        let ctx = ValidationContext::new(true);

        let safe_path = PathBuf::from("safe_dir/file.txt");
        let result = SafePath::validate_with_context(&safe_path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "safe path through a real dir should succeed: {result:?}"
        );

        let evil_path = PathBuf::from("evil/payload.txt");
        let result = SafePath::validate_with_context(&evil_path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink escape must be caught with symlinks_allowed: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_free_fast_path_still_rejects_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Symlink-free fast path (no symlinks allowed, none seen)
        let ctx = ValidationContext::new(false);

        // These should still be caught by component-level checks
        let path = PathBuf::from("../escape.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "parent traversal must be caught in fast path"
        );
    }

    #[test]
    fn test_validate_with_context_no_parent() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Single-component path has dest itself as parent
        let ctx = ValidationContext::new(false);

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "single component should work: {result:?}");
    }

    // --- Tests for archive root entry handling (issue #113) ---

    #[test]
    fn test_archive_root_dot_is_accepted() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // "." is the archive root directory — produced by `tar -C /dir .`
        let result = SafePath::validate(Path::new("."), &dest, &config);
        assert!(
            result.is_ok(),
            "archive root '.' must be accepted: {result:?}"
        );
        assert_eq!(result.expect("safe").as_path(), Path::new(""));
    }

    #[test]
    fn test_archive_root_dot_slash_is_accepted() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // "./" is an alternate form of the archive root directory entry
        let result = SafePath::validate(Path::new("./"), &dest, &config);
        assert!(
            result.is_ok(),
            "archive root './' must be accepted: {result:?}"
        );
        assert_eq!(result.expect("safe").as_path(), Path::new(""));
    }

    #[test]
    fn test_archive_root_dot_dot_still_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // ".." must still be rejected — it is a traversal attempt, not an
        // archive root
        let result = SafePath::validate(Path::new(".."), &dest, &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "'..' must be rejected as path traversal"
        );
    }

    #[test]
    fn test_archive_root_dot_dot_slash_still_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = ["./..", "./../../etc", "../foo", "./../etc/passwd"];
        for p in paths {
            let result = SafePath::validate(Path::new(p), &dest, &config);
            assert_matches!(
                result,
                Err(ArchiveError::PathTraversal { .. }),
                "path '{p}' must be rejected as path traversal"
            );
        }
    }

    // --- Tests for GHSA-wcmx-7f9h-5mv5 (case-insensitive prefix bypass) ---

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn test_paths_start_with_rejects_sibling_sharing_name_prefix_ghsa_wcmx() {
        // GHSA-wcmx-7f9h-5mv5: the previous implementation compared paths as
        // raw strings, so `/tmp/destevil`.starts_with(`/tmp/dest`) was true
        // even though `destevil` is a sibling directory, not a subdirectory
        // of `dest`.
        let base = Path::new("/tmp/dest");
        let sibling = Path::new("/tmp/destevil");
        assert!(
            !paths_start_with(sibling, base),
            "sibling directory sharing a name prefix must not be treated as contained"
        );
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn test_paths_start_with_accepts_genuine_subdirectory() {
        let base = Path::new("/tmp/dest");
        let child = Path::new("/tmp/dest/sub");
        assert!(
            paths_start_with(child, base),
            "genuine subdirectory must still be accepted as contained"
        );
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn test_paths_start_with_is_case_insensitive() {
        let base = Path::new("/tmp/dest");
        let child = Path::new("/tmp/Dest/sub");
        assert!(
            paths_start_with(child, base),
            "differing-case containment must still be accepted on case-insensitive filesystems"
        );
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn test_paths_start_with_rejects_when_base_has_more_components_than_path() {
        // Regression for a `break`-instead-of-`return false` mutant: when
        // `base` has more components than `path`, the `path` component
        // iterator is exhausted mid-loop and the function must reject
        // immediately, not fall through the loop to the trailing `true`.
        let base = Path::new("/tmp/dest/sub/extra");
        let shorter = Path::new("/tmp/dest/sub");
        assert!(
            !paths_start_with(shorter, base),
            "a path shorter than base must never be treated as containing base"
        );
    }

    fn default_config() -> SecurityConfig {
        SecurityConfig::default()
    }

    #[test]
    fn test_portable_component_message_is_portable_flavoured() {
        let err = check_component_for(PathModel::Portable, OsStr::new("a?b"), &default_config())
            .expect_err("`?` must be refused");
        assert!(
            err.to_string()
                .contains("not portable (contains a character Windows refuses)"),
            "{err}"
        );
    }

    #[test]
    fn test_host_component_rules_are_empty_off_windows() {
        for name in ["a?b", "a<b", "a\u{1}b", "a:b", "CON", "x."] {
            check_component_on(
                PathModel::Host,
                HostOs::Other,
                OsStr::new(name),
                &default_config(),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn test_host_component_refuses_portable_hazards_on_windows() {
        for name in [
            "a?b", "a<b", "a>b", "a\"b", "a|b", "a*b", "a\u{1}b", "a:b", "x.",
        ] {
            let err = check_component_on(
                PathModel::Host,
                HostOs::Windows,
                OsStr::new(name),
                &default_config(),
            )
            .expect_err(name);
            assert_matches!(err, ArchiveError::SecurityViolation { .. });
            assert!(!err.to_string().contains("not portable"), "{err}");
        }
    }

    #[test]
    fn test_component_error_escapes_control_characters() {
        for (model, host) in [
            (PathModel::Host, HostOs::Windows),
            (PathModel::Portable, HostOs::Other),
        ] {
            let err =
                check_component_on(model, host, OsStr::new("a\u{1b}[31mb"), &default_config())
                    .expect_err("control character");
            let text = err.to_string();
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(text.contains("\\u{1b}"), "{text:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_non_utf8_component_refused_by_windows_host_model() {
        use std::os::unix::ffi::OsStrExt;
        let err = check_component_on(
            PathModel::Host,
            HostOs::Windows,
            OsStr::from_bytes(b"a\xffb"),
            &default_config(),
        )
        .expect_err("non-UTF-8");
        assert_matches!(err, ArchiveError::SecurityViolation { .. });
    }

    #[test]
    #[cfg(windows)]
    fn test_host_refuses_forbidden_character_name_and_symlink_target_on_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::permissive();
        assert_matches!(
            SafePath::validate(Path::new("dir/a?b"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
        let link = SafePath::validate(Path::new("link"), &dest, &config).expect("link path");
        assert_matches!(
            crate::types::SafeSymlink::validate(&link, Path::new("a<b"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_planted_in_nested_parent_is_refused() {
        let (_temp, dest) = create_test_dest();
        let outside = TempDir::new().expect("failed to create temp dir");
        let config = default_config();
        let parent = dest.as_path().join("d1/d2");
        std::fs::create_dir_all(&parent).expect("should create dir");

        std::fs::remove_dir(&parent).expect("remove");
        std::os::unix::fs::symlink(outside.path(), &parent).expect("symlink");

        let ctx = ValidationContext::new(false);
        let result = SafePath::validate_with_context(Path::new("d1/d2/f"), &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "{result:?}"
        );
    }

    struct RecordingFs(std::cell::RefCell<Vec<PathBuf>>);

    impl crate::security::fs_view::FsView for RecordingFs {
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
            HostFs.is_symlink(path)
        }

        fn canonicalize(
            &self,
            path: &Path,
            root: &DestDir,
        ) -> std::io::Result<crate::security::fs_view::Containment> {
            self.0.borrow_mut().push(path.to_path_buf());
            HostFs.canonicalize(path, root)
        }
    }

    #[test]
    fn test_parent_equal_to_dest_is_not_canonicalized() {
        let (_temp, dest) = create_test_dest();
        let config = default_config();
        let view = RecordingFs(std::cell::RefCell::default());

        SafePath::validate_in(Path::new("file.txt"), &dest, &config, &view).expect("valid");
        assert!(view.0.borrow().is_empty(), "{:?}", view.0.borrow());

        std::fs::create_dir(dest.as_path().join("sub")).expect("mkdir");
        SafePath::validate_in(Path::new("sub/file.txt"), &dest, &config, &view).expect("valid");
        assert_eq!(*view.0.borrow(), [dest.as_path().join("sub")]);
    }

    #[test]
    #[cfg(unix)]
    fn test_symlinked_child_of_dest_is_still_refused() {
        let (_temp, dest) = create_test_dest();
        let outside = TempDir::new().expect("failed to create temp dir");
        std::os::unix::fs::symlink(outside.path(), dest.as_path().join("link")).expect("symlink");

        let ctx = ValidationContext::new(false);
        let result =
            SafePath::validate_with_context(Path::new("link/f"), &dest, &default_config(), &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "{result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn walker_backed_context_defers_the_parent_probe_to_the_write() {
        use crate::formats::pinned_dir::PinnedRoot;
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("setup");
        let base = temp.path().canonicalize().expect("setup");
        let outside = base.join("outside");
        std::fs::create_dir(base.join("dest")).expect("setup");
        std::fs::create_dir(&outside).expect("setup");
        symlink(&outside, base.join("dest/link")).expect("setup");
        let dest = DestDir::new(base.join("dest")).expect("setup");
        let config = SecurityConfig::default();
        let path = Path::new("link/x.txt");

        let probed = SafePath::validate_with_context(
            path,
            &dest,
            &config,
            &ValidationContext::<HostFs>::new(false),
        );
        assert_matches!(probed, Err(ArchiveError::PathTraversal { .. }));

        let root = PinnedRoot::open_for_test(&base.join("dest")).expect("setup");
        let deferred =
            ValidationContext::<HostFs>::new(false).with_walker(root.backs_parent_probe());
        SafePath::validate_with_context(path, &dest, &config, &deferred)
            .expect("the walker vets the parent at write time");
    }

    #[cfg(unix)]
    struct NameTooLongFs;

    #[cfg(unix)]
    impl crate::security::fs_view::FsView for NameTooLongFs {
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
            HostFs.is_symlink(path)
        }

        fn canonicalize(
            &self,
            _path: &Path,
            _root: &DestDir,
        ) -> std::io::Result<crate::security::fs_view::Containment> {
            Err(std::io::ErrorKind::InvalidFilename.into())
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_name_past_the_host_limit_is_left_to_the_walker_only_when_it_vets_the_parent() {
        use crate::formats::pinned_dir::PinnedRoot;

        let (temp, dest) = create_test_dest();
        let config = default_config();
        let view = NameTooLongFs;
        let path = Path::new("sub/f");

        let resolved = SafePath::<Resolved>::validate_with_context_in(
            path,
            &dest,
            &config,
            &ValidationContext::<NameTooLongFs>::new(true),
            &view,
        );
        assert_matches!(resolved, Err(ArchiveError::Io(ref e))
            if e.kind() == std::io::ErrorKind::InvalidFilename, "{resolved:?}");

        let root = PinnedRoot::open_for_test(temp.path()).expect("setup");
        let walked =
            ValidationContext::<NameTooLongFs>::new(true).with_walker(root.backs_parent_probe());
        SafePath::validate_with_context_in(path, &dest, &config, &walked, &view)
            .expect("the walker decides a name past the host limit");
    }
}
