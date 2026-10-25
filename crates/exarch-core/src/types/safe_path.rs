//! Validated safe path type for archive extraction.

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::security::context::ValidationContext;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;

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
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default().validate()?;
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
pub struct SafePath(PathBuf);

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
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::SafePath;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let config = SecurityConfig::default().validate()?;
    ///
    /// let safe = SafePath::validate(&PathBuf::from("valid/path.txt"), &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
    ) -> Result<Self> {
        Self::validate_in(path, dest, config, &HostFs)
    }

    /// Validates `path` against `view` instead of the real filesystem.
    pub(crate) fn validate_in<V: FsView>(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
        view: &V,
    ) -> Result<Self> {
        let ctx = ValidationContext::new(config.allowed.symlinks);
        Self::validate_with_context_in(path, dest, config, &ctx, view)
    }

    /// Validates with optimization context that can skip `canonicalize()`.
    ///
    /// When a `ValidationContext` carries a `DirCache` reference, parent
    /// directories that we created are trusted without a `canonicalize()`
    /// syscall. When symlinks are impossible (disabled in config AND none
    /// seen), the full-path `canonicalize()` is also skipped.
    ///
    /// All other validation steps (null bytes, absolute paths, parent
    /// traversal, depth, banned components, prefix check) are always
    /// performed regardless of context.
    pub(crate) fn validate_with_context(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
        ctx: &ValidationContext,
    ) -> Result<Self> {
        Self::validate_with_context_in(path, dest, config, ctx, &HostFs)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one cohesive sequence; splitting it would obscure the order of checks"
    )]
    pub(crate) fn validate_with_context_in<V: FsView>(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
        ctx: &ValidationContext,
        view: &V,
    ) -> Result<Self> {
        // Reject empty paths explicitly
        if path.is_empty() {
            return Err(ArchiveError::SecurityViolation {
                reason: EMPTY_PATH_REASON.into(),
            });
        }

        // Archive root entries ("." or "./") represent the extraction directory
        // itself. They are produced by `tar -C /dir .` and are always safe.
        // Return immediately — no further validation needed.
        if path == Path::new(".") || path == Path::new("./") {
            return Ok(Self(PathBuf::new()));
        }

        // 1. Check for null bytes
        if has_null_bytes(path) {
            return Err(ArchiveError::SecurityViolation {
                reason: format!("path contains null bytes: {}", path.display()),
            });
        }

        // 2. Check for absolute paths
        if path.is_absolute() && !config.allowed.absolute_paths {
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

                    if cfg!(windows) {
                        check_windows_component(comp, config)?;
                    }

                    if has_banned_components {
                        let comp_str = comp
                            .to_str()
                            .map_or_else(|| comp.to_string_lossy(), Cow::Borrowed);

                        if !config.is_path_component_allowed(&comp_str) {
                            return Err(ArchiveError::SecurityViolation {
                                reason: format!("banned path component: {comp_str}"),
                            });
                        }
                    }

                    normalized.push(component);
                }
                Component::CurDir => {
                    needs_normalization = true;
                }
                Component::RootDir | Component::Prefix(_) => {
                    if !config.allowed.absolute_paths {
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
        if depth > config.max_path_depth {
            return Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "path depth {} exceeds maximum {}",
                    depth, config.max_path_depth
                ),
            });
        }

        let final_path = if needs_normalization {
            Cow::Owned(normalized)
        } else {
            Cow::Borrowed(path)
        };

        // Verify resolved path stays within destination
        let resolved = dest.as_path().join(final_path.as_ref());

        // Parent canonicalization: skip when parent is trusted (in DirCache)
        if let Some(parent) = resolved.parent()
            && !ctx.is_trusted_parent(parent)
        {
            match view.canonicalize(parent) {
                Ok(canonical_parent) => {
                    if !paths_start_with(&canonical_parent, dest.as_path()) {
                        return Err(ArchiveError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(ArchiveError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to canonicalize parent: {e}"),
                    )));
                }
            }
        }

        // Full path canonicalization: skip when symlinks are impossible
        if ctx.needs_full_canonicalize() {
            match view.canonicalize(&resolved) {
                Ok(canonical) => {
                    if !paths_start_with(&canonical, dest.as_path()) {
                        return Err(ArchiveError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !paths_start_with(&resolved, dest.as_path()) {
                        return Err(ArchiveError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) => {
                    return Err(ArchiveError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to canonicalize path: {e}"),
                    )));
                }
            }
        } else {
            // Symlinks impossible -- prefix check is still mandatory
            if !paths_start_with(&resolved, dest.as_path()) {
                return Err(ArchiveError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
        }

        Ok(Self(final_path.into_owned()))
    }

    /// Creates a `SafePath` without validation (INTERNAL USE ONLY).
    ///
    /// # Safety
    ///
    /// This bypasses all validation checks. The caller MUST ensure that:
    /// - The path has been validated by equivalent checks elsewhere
    /// - The path is relative (not absolute)
    /// - The path contains no `..` components
    /// - The path resolves within the destination directory
    ///
    /// This is only used internally when path has already been validated
    /// through a different mechanism (e.g., hardlink validation).
    pub(crate) fn new_unchecked(path: PathBuf) -> Self {
        Self(path)
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
pub(crate) fn check_windows_component(
    comp: &OsStr,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    match windows_component_hazard(comp) {
        None => Ok(()),
        Some(WindowsComponentHazard::ReservedDeviceName)
            if config.allowed.windows_reserved_names =>
        {
            Ok(())
        }
        Some(WindowsComponentHazard::ReservedDeviceName) => Err(ArchiveError::SecurityViolation {
            reason: format!("Windows reserved device name: {}", comp.display()),
        }),
        Some(WindowsComponentHazard::StreamSeparator) => {
            Err(stream_separator_error(&comp.display().to_string()))
        }
        Some(WindowsComponentHazard::TrailingDotOrSpace) => Err(ArchiveError::SecurityViolation {
            reason: format!("path component ends with '.' or ' ': {}", comp.display()),
        }),
    }
}

/// The error for a path component containing `:`, which Windows treats as a
/// drive or alternate-data-stream separator.
pub(crate) fn stream_separator_error(comp: &str) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!("path component contains ':': {comp}"),
    }
}

/// Returns `true` if `comp` names a Windows legacy device.
///
/// The name is the text before the first `.`, with trailing spaces trimmed,
/// compared ASCII case-insensitively against `CON`, `PRN`, `AUX`, `NUL`,
/// `COM0`-`COM9`, `LPT0`-`LPT9`, the superscript forms `COM¹²³` / `LPT¹²³`,
/// `CONIN$` and `CONOUT$`. Pure and platform-independent; callers decide
/// whether to apply it.
///
/// # Examples
///
/// ```
/// use exarch_core::types::safe_path::is_windows_reserved_component;
/// use std::ffi::OsStr;
///
/// assert!(is_windows_reserved_component(OsStr::new("NUL.tar.gz")));
/// assert!(!is_windows_reserved_component(OsStr::new("console.txt")));
/// ```
#[must_use]
pub fn is_windows_reserved_component(comp: &OsStr) -> bool {
    const PLAIN: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
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
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

/// Case-insensitive path prefix check for macOS/Windows.
///
/// On case-insensitive filesystems (macOS, Windows), attackers can bypass
/// path validation using different case (e.g., `../../USERS/victim/.ssh/`).
///
/// Compares `path` and `base` component-by-component rather than as raw
/// strings, so a shared name prefix without a component boundary (e.g. base
/// `/tmp/dest` against sibling `/tmp/destevil`) is correctly rejected. See
/// GHSA-wcmx-7f9h-5mv5.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn paths_start_with(path: &Path, base: &Path) -> bool {
    let mut path_components = path.components();
    for base_component in base.components() {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        let path_str = path_component.as_os_str().to_string_lossy().to_lowercase();
        let base_str = base_component.as_os_str().to_string_lossy().to_lowercase();
        if path_str != base_str {
            return false;
        }
    }
    true
}

/// Case-sensitive path prefix check for Unix (not macOS).
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn paths_start_with(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
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
    use crate::formats::common::DirCache;
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

    // Empty path handling test (MED-004)
    #[test]
    fn test_empty_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

        let path = PathBuf::from("foo/bar/baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), path.as_path());
    }

    #[test]
    fn test_safe_path_reject_parent_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

        let path = PathBuf::from("/etc/passwd");
        let result = SafePath::validate(&path, &dest, &config);
        assert_matches!(result, Err(ArchiveError::PathTraversal { .. }));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_reject_absolute_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        config.allowed.absolute_paths = true;
        let config = config.validate().expect("valid config");

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
        config.allowed.absolute_paths = true;
        let config = config.validate().expect("valid config");

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
        config.max_path_depth = 3;
        let config = config.validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

        let path = PathBuf::from("foo/./bar/./baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));
    }

    #[test]
    fn test_safe_path_null_bytes() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

        let safe1 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let safe2 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");

        assert_eq!(safe1, safe2);
    }

    #[test]
    fn test_safe_path_clone() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

        let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let cloned = safe.clone();

        assert_eq!(safe, cloned);
    }

    // Test for empty path (MED-004)
    #[test]
    fn test_safe_path_empty() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        config.max_path_depth = 5;
        let config = config.validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");
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
        let config = SecurityConfig::default()
            .with_allow_windows_reserved_names(true)
            .validate()
            .expect("valid config");

        assert!(check_windows_component(OsStr::new("NUL.tar.gz"), &config).is_ok());
        assert!(check_windows_component(OsStr::new("CONIN$"), &config).is_ok());
        assert_matches!(
            check_windows_component(OsStr::new("a:b"), &config),
            Err(ArchiveError::SecurityViolation { .. })
        );
    }

    #[test]
    fn test_check_windows_component_permissive_preset_still_rejects() {
        let config = SecurityConfig::permissive()
            .validate()
            .expect("valid config");

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
        let config = SecurityConfig::default()
            .with_allow_windows_reserved_names(true)
            .validate()
            .expect("valid config");
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
        let config = SecurityConfig::default().validate().expect("valid config");
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
        use crate::security::fs_view::VirtualTree;

        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .validate()
            .expect("valid config");
        let mut tree = VirtualTree::new(dest.as_path());
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
            "COM\u{2074}",
        ] {
            assert!(!is_windows_reserved_component(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_reserved_names_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");
        let permissive = SecurityConfig::permissive()
            .validate()
            .expect("valid config");

        for name in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"] {
            let path = PathBuf::from(format!("folder/{name}.txt"));
            for cfg in [&config, &permissive] {
                assert!(matches!(
                    SafePath::validate(&path, &dest, cfg),
                    Err(ArchiveError::SecurityViolation { .. })
                ));
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_reserved_names_opt_out() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default()
            .with_allow_windows_reserved_names(true)
            .validate()
            .expect("valid config");

        assert!(SafePath::validate(Path::new("folder/CON.txt"), &dest, &config).is_ok());
        assert!(matches!(
            SafePath::validate(Path::new("folder/a:stream"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_colon_rejected() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

        assert!(matches!(
            SafePath::validate(Path::new("file.txt:stream"), &dest, &config),
            Err(ArchiveError::SecurityViolation { .. })
        ));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_safe_path_reserved_names_accepted_off_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

        assert!(SafePath::validate(Path::new("folder/CON.txt"), &dest, &config).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_parent_chain() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
    fn test_validate_with_context_trusted_parent_skips_canonicalize() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create a real directory and register it in DirCache
        let sub_dir = dest.as_path().join("trusted_dir");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

        // Validate a path whose parent is in DirCache
        let path = PathBuf::from("trusted_dir/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "trusted parent should succeed: {result:?}");
    }

    #[test]
    fn test_validate_with_context_untrusted_parent_still_validates() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        let dir_cache = DirCache::new(); // empty cache
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

        // Path whose parent is NOT in DirCache and doesn't exist
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
        let config = SecurityConfig::default().validate().expect("valid config"); // symlinks = false

        // No dir_cache, no symlinks -> fast path (no canonicalize)
        let ctx = ValidationContext::new(false);
        let path = PathBuf::from("some/path/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "symlink-free fast path should work");
    }

    #[test]
    fn test_validate_with_context_symlink_seen_disables_fast_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create a symlink pointing outside dest
        let malicious_link = temp.path().join("evil_dir");
        symlink("/tmp", &malicious_link).expect("failed to create symlink");

        // Even without context optimization, symlink attack must be caught.
        // Parent is NOT in DirCache so canonicalize will run.
        let dir_cache = DirCache::new();
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

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
    fn test_preexisting_symlink_in_dest_with_trusted_parent() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create a real subdirectory and register in DirCache
        let sub_dir = dest.as_path().join("subdir");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        // Create a symlink INSIDE that directory pointing outside
        let evil_link = sub_dir.join("escape");
        symlink("/tmp", &evil_link).expect("failed to create symlink");

        // The resolved path is dest/subdir/escape/payload.txt. Its parent is
        // dest/subdir/escape, which is NOT in DirCache (only dest/subdir is).
        // Therefore the parent canonicalization layer still runs and catches
        // the symlink escape regardless of the symlink-free fast path.
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);
        let path = PathBuf::from("subdir/escape/payload.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "parent canonicalization must catch symlink even in fast path: {result:?}"
        );

        // With symlink_seen marked, both parent AND full canonicalize run
        let mut ctx_with_symlink = ValidationContext::new(false).with_dir_cache(&dir_cache);
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
    fn test_symlink_as_direct_child_of_trusted_parent() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create subdir and register in DirCache
        let sub_dir = dest.as_path().join("trusted");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        // Create symlink as a direct child: trusted/link -> /tmp
        let link = sub_dir.join("link");
        symlink("/tmp", &link).expect("failed to create symlink");

        // Path "trusted/link" has parent dest/trusted which IS in DirCache.
        // Parent canonicalize is skipped. But the symlink-free fast path only
        // does prefix check on the un-resolved path, which passes since the
        // path textually starts with dest. This is acceptable: the file being
        // extracted IS a direct child name, not a traversal through a symlink
        // directory. The symlink "link" itself would only be created if the
        // archive contained a symlink entry, which is blocked by config.
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);
        let path = PathBuf::from("trusted/link");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "direct child of trusted parent is a file name, not traversal: {result:?}"
        );
    }

    #[test]
    fn test_validate_backward_compat_same_result() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        let test_paths = vec![
            PathBuf::from("file.txt"),
            PathBuf::from("dir/file.txt"),
            PathBuf::from("a/b/c/file.txt"),
            PathBuf::from("./normalized.txt"),
        ];

        for path in &test_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks);
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
        let config = SecurityConfig::default().validate().expect("valid config");

        let error_paths = vec![
            PathBuf::from("../escape"),
            PathBuf::from(""),
            PathBuf::from("project/.git/config"),
        ];

        for path in &error_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks);
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
    fn test_validate_with_context_symlinks_allowed_and_dir_cache() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create dir and register in cache
        let sub = dest.as_path().join("safe_dir");
        let mut cache = DirCache::new();
        cache.ensure_dir(&sub).expect("should create dir");

        // Create symlink pointing outside in another location
        let evil = dest.as_path().join("evil");
        symlink("/tmp", &evil).expect("failed to create symlink");

        // With symlinks_allowed=true: needs_full_canonicalize is true,
        // so the full canonicalize runs and catches the symlink
        let ctx = ValidationContext::new(true).with_dir_cache(&cache);

        let safe_path = PathBuf::from("safe_dir/file.txt");
        let result = SafePath::validate_with_context(&safe_path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "safe path through cached dir should succeed: {result:?}"
        );

        let evil_path = PathBuf::from("evil/payload.txt");
        let result = SafePath::validate_with_context(&evil_path, &dest, &config, &ctx);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "symlink escape must be caught with symlinks_allowed + dir_cache: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_free_fast_path_still_rejects_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
    fn test_validate_with_context_dir_cache_created_vs_preexisting() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");

        // Create directory manually (pre-existing, NOT in DirCache)
        let preexisting = dest.as_path().join("preexisting");
        std::fs::create_dir(&preexisting).expect("failed to create dir");

        // Create directory via DirCache (tracked)
        let tracked = dest.as_path().join("tracked");
        let mut cache = DirCache::new();
        cache.ensure_dir(&tracked).expect("should create dir");

        let ctx = ValidationContext::new(false).with_dir_cache(&cache);

        // Pre-existing dir is NOT trusted (not in cache), so canonicalize runs
        let path1 = PathBuf::from("preexisting/file.txt");
        let result1 = SafePath::validate_with_context(&path1, &dest, &config, &ctx);
        assert!(
            result1.is_ok(),
            "pre-existing dir should still validate: {result1:?}"
        );

        // Tracked dir IS trusted (in cache), parent canonicalize is skipped
        let path2 = PathBuf::from("tracked/file.txt");
        let result2 = SafePath::validate_with_context(&path2, &dest, &config, &ctx);
        assert!(result2.is_ok(), "tracked dir should validate: {result2:?}");
    }

    #[test]
    fn test_validate_with_context_no_parent() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

        // Single-component path has dest itself as parent
        let cache = DirCache::new();
        let ctx = ValidationContext::new(false).with_dir_cache(&cache);

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "single component should work: {result:?}");
    }

    // --- Tests for archive root entry handling (issue #113) ---

    #[test]
    fn test_archive_root_dot_is_accepted() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
}
