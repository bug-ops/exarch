//! Path filtering logic for archive creation.
//!
//! This module provides utilities for filtering files during archive creation
//! based on patterns, hidden file rules, and size constraints.

use crate::ArchiveError;
use crate::Result;
use crate::SkipKind;
use crate::Violation;
use crate::creation::config::CreationConfig;
use std::path::Path;
use std::path::PathBuf;

/// Returns why the entry at `archive_path` is left out of the archive, or
/// `None` when it is kept.
///
/// An entry is left out when it is hidden and `include_hidden` is false, or
/// when it matches an exclude pattern. The size limit is checked separately,
/// where the size is known.
#[must_use]
pub(crate) fn skip_reason(archive_path: &Path, config: &CreationConfig) -> Option<SkipKind> {
    if !config.include_hidden && is_hidden(archive_path) {
        return Some(SkipKind::Hidden);
    }
    config
        .exclude_patterns
        .iter()
        .any(|pattern| pattern.matches(archive_path))
        .then_some(SkipKind::Excluded)
}

/// Checks if a path is hidden (starts with '.').
///
/// On Unix-like systems, files starting with '.' are considered hidden.
/// This function checks the file name component, not the full path.
#[must_use]
pub(crate) fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.as_encoded_bytes().starts_with(b"."))
}

/// Computes the archive path from source path.
///
/// Applies `strip_prefix` if configured. The archive path is relative
/// to the root directory being archived.
///
/// # Errors
///
/// Returns an error if the source path is not under the root directory.
///
/// A `strip_prefix` that does not match the computed relative path is
/// ignored; the unstripped relative path is used.
pub(crate) fn compute_archive_path(
    source_path: &Path,
    root: &Path,
    config: &CreationConfig,
) -> Result<PathBuf> {
    // Compute relative path from root
    let relative = source_path.strip_prefix(root).map_err(|_| {
        ArchiveError::from(Violation::SourceOutsideRoot {
            path: source_path.display().to_string().into(),
            root: root.display().to_string().into(),
        })
    })?;

    // Apply strip_prefix if configured
    if let Some(strip) = &config.strip_prefix
        && let Ok(stripped) = relative.strip_prefix(strip)
    {
        return Ok(stripped.to_path_buf());
    }
    // If strip_prefix doesn't match, use original relative path

    Ok(relative.to_path_buf())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use crate::creation::exclude_pattern::ExcludePattern;
    use std::path::PathBuf;

    fn pattern(text: &str) -> ExcludePattern {
        ExcludePattern::try_from(text).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_are_hidden_or_excluded_by_their_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let hidden = Path::new(OsStr::from_bytes(b".\xff"));
        assert!(is_hidden(hidden));
        let config = CreationConfig::default();
        assert_eq!(skip_reason(hidden, &config), Some(SkipKind::Hidden));
        let excluded = Path::new(OsStr::from_bytes(b"a/\xfe.tmp"));
        assert_eq!(skip_reason(excluded, &config), Some(SkipKind::Excluded));
    }

    #[test]
    fn test_is_hidden_dotfiles() {
        assert!(is_hidden(Path::new(".gitignore")));
        assert!(is_hidden(Path::new(".env")));
        assert!(is_hidden(Path::new(".hidden")));
        assert!(is_hidden(Path::new("dir/.DS_Store")));
    }

    #[test]
    fn test_is_hidden_regular_files() {
        assert!(!is_hidden(Path::new("main.rs")));
        assert!(!is_hidden(Path::new("README.md")));
        assert!(!is_hidden(Path::new("file.txt")));
        assert!(!is_hidden(Path::new("dir/normal.rs")));
    }

    #[test]
    fn test_is_hidden_empty_path() {
        // Edge case: empty path component
        assert!(!is_hidden(Path::new("")));
    }

    #[test]
    fn test_compute_archive_path_basic() {
        let config = CreationConfig::default();
        let root = Path::new("/home/user/project");
        let source = Path::new("/home/user/project/src/main.rs");

        let result = compute_archive_path(source, root, &config).unwrap();
        assert_eq!(result, Path::new("src/main.rs"));
    }

    #[test]
    fn test_compute_archive_path_strip_prefix() {
        let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("src")));
        let root = Path::new("/home/user/project");
        let source = Path::new("/home/user/project/src/main.rs");

        let result = compute_archive_path(source, root, &config).unwrap();
        assert_eq!(result, Path::new("main.rs"));
    }

    #[test]
    fn test_compute_archive_path_strip_prefix_no_match() {
        let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("other")));
        let root = Path::new("/home/user/project");
        let source = Path::new("/home/user/project/src/main.rs");

        // If strip_prefix doesn't match, use original relative path
        let result = compute_archive_path(source, root, &config).unwrap();
        assert_eq!(result, Path::new("src/main.rs"));
    }

    #[test]
    fn test_compute_archive_path_not_under_root() {
        let config = CreationConfig::default();
        let root = Path::new("/home/user/project");
        let source = Path::new("/home/other/file.txt");

        let result = compute_archive_path(source, root, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_archive_path_same_as_root() {
        let config = CreationConfig::default();
        let root = Path::new("/home/user/project");
        let source = Path::new("/home/user/project");

        let result = compute_archive_path(source, root, &config).unwrap();
        assert_eq!(result, Path::new(""));
    }

    #[test]
    fn test_skip_reason_hidden_files() {
        let config = CreationConfig::default();
        assert_eq!(
            skip_reason(Path::new(".env"), &config),
            Some(SkipKind::Hidden)
        );
        let config = config.with_include_hidden(true);
        assert_eq!(skip_reason(Path::new(".env"), &config), None);
    }

    #[test]
    fn test_skip_reason_default_patterns_exclude() {
        let config = CreationConfig::default().with_include_hidden(true);
        for path in [".git", ".DS_Store", "file.tmp", "a/.git/HEAD"] {
            assert_eq!(
                skip_reason(Path::new(path), &config),
                Some(SkipKind::Excluded),
                "{path}"
            );
        }
    }

    #[test]
    fn test_skip_reason_normal_files() {
        let config = CreationConfig::default();
        for path in ["main.rs", "README.md", "src/lib.rs"] {
            assert_eq!(skip_reason(Path::new(path), &config), None);
        }
    }

    #[test]
    fn test_skip_reason_combines_rules() {
        let config = CreationConfig::default()
            .with_exclude_patterns(vec![pattern("*.log"), pattern("temp*")])
            .with_include_hidden(false);

        assert_eq!(
            skip_reason(Path::new(".hidden"), &config),
            Some(SkipKind::Hidden)
        );
        assert_eq!(
            skip_reason(Path::new("debug.log"), &config),
            Some(SkipKind::Excluded)
        );
        assert_eq!(
            skip_reason(Path::new("temp_file"), &config),
            Some(SkipKind::Excluded)
        );
        assert_eq!(skip_reason(Path::new("main.rs"), &config), None);
    }
}
