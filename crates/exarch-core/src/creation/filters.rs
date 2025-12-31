//! Path filtering logic for archive creation.
//!
//! This module provides utilities for filtering files during archive creation
//! based on patterns, hidden file rules, and size constraints.

use crate::ExtractionError;
use crate::Result;
use crate::creation::config::CreationConfig;
use std::path::Path;
use std::path::PathBuf;

/// Checks if a path should be skipped based on configuration.
///
/// A path is skipped if:
/// - It's a hidden file and `include_hidden` is false
/// - It matches an exclude pattern
/// - Its size exceeds `max_file_size` (checked externally)
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::filters;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let hidden_file = Path::new(".gitignore");
/// assert!(filters::should_skip(hidden_file, &config));
///
/// let normal_file = Path::new("main.rs");
/// assert!(!filters::should_skip(normal_file, &config));
/// ```
#[must_use]
pub fn should_skip(path: &Path, config: &CreationConfig) -> bool {
    // Skip hidden files unless configured to include them
    if !config.include_hidden && is_hidden(path) {
        return true;
    }

    // Skip if matches any exclude pattern
    for pattern in &config.exclude_patterns {
        if matches_pattern(path, pattern) {
            return true;
        }
    }

    false
}

/// Checks if a path is hidden (starts with '.').
///
/// On Unix-like systems, files starting with '.' are considered hidden.
/// This function checks the file name component, not the full path.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::filters;
/// use std::path::Path;
///
/// assert!(filters::is_hidden(Path::new(".gitignore")));
/// assert!(filters::is_hidden(Path::new("dir/.hidden")));
/// assert!(!filters::is_hidden(Path::new("visible.txt")));
/// assert!(!filters::is_hidden(Path::new("dir/normal.rs")));
/// ```
#[must_use]
pub fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

/// Matches path against glob-style pattern.
///
/// Supports:
/// - Exact match: `".git"` matches only `.git`
/// - Extension wildcard: `"*.txt"` matches files ending with `.txt`
/// - Prefix wildcard: `"temp*"` matches files starting with `temp`
/// - Component match: matches against any path component, not just the full
///   path
///
/// # Examples
///
/// ```
/// use exarch_core::creation::filters;
/// use std::path::Path;
///
/// // Exact match
/// assert!(filters::matches_pattern(Path::new(".git"), ".git"));
/// assert!(filters::matches_pattern(Path::new("dir/.git"), ".git"));
///
/// // Extension wildcard
/// assert!(filters::matches_pattern(Path::new("file.tmp"), "*.tmp"));
/// assert!(filters::matches_pattern(Path::new("dir/test.tmp"), "*.tmp"));
///
/// // Prefix wildcard
/// assert!(filters::matches_pattern(Path::new("temp_file"), "temp*"));
/// assert!(!filters::matches_pattern(Path::new("file_temp"), "temp*"));
/// ```
#[must_use]
pub fn matches_pattern(path: &Path, pattern: &str) -> bool {
    // Check all path components using OsStr to avoid allocations
    for component in path.components() {
        let component_os = component.as_os_str();
        // Only convert to str when necessary
        if let Some(component_str) = component_os.to_str()
            && pattern_matches(component_str, pattern)
        {
            return true;
        }
    }

    // Also check the full path string for patterns like "*.ext"
    // Only convert to string once
    if let Some(path_str) = path.to_str()
        && pattern_matches(path_str, pattern)
    {
        return true;
    }

    false
}

/// Matches a string against a simple glob pattern.
fn pattern_matches(s: &str, pattern: &str) -> bool {
    if pattern == s {
        // Exact match
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        // Prefix wildcard: "temp*"
        return s.starts_with(prefix);
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        // Extension wildcard: "*.txt"
        return s.ends_with(suffix);
    }

    false
}

/// Computes the archive path from source path.
///
/// Applies `strip_prefix` if configured. The archive path is relative
/// to the root directory being archived.
///
/// # Errors
///
/// Returns an error if:
/// - The source path is not under the root directory
/// - The `strip_prefix` does not match the computed relative path
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::filters;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let root = Path::new("/home/user/project");
/// let source = Path::new("/home/user/project/src/main.rs");
///
/// let archive_path = filters::compute_archive_path(source, root, &config).unwrap();
/// assert_eq!(archive_path, Path::new("src/main.rs"));
/// ```
pub fn compute_archive_path(
    source_path: &Path,
    root: &Path,
    config: &CreationConfig,
) -> Result<PathBuf> {
    // Compute relative path from root
    let relative =
        source_path
            .strip_prefix(root)
            .map_err(|_| ExtractionError::SecurityViolation {
                reason: format!(
                    "path {} is not under root directory: {}",
                    source_path.display(),
                    root.display()
                ),
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
    fn test_matches_pattern_exact() {
        assert!(matches_pattern(Path::new(".git"), ".git"));
        assert!(matches_pattern(Path::new(".DS_Store"), ".DS_Store"));
        assert!(matches_pattern(Path::new("dir/.git"), ".git"));
        assert!(!matches_pattern(Path::new(".github"), ".git"));
    }

    #[test]
    fn test_matches_pattern_extension() {
        assert!(matches_pattern(Path::new("file.txt"), "*.txt"));
        assert!(matches_pattern(Path::new("test.tmp"), "*.tmp"));
        assert!(matches_pattern(Path::new("dir/file.log"), "*.log"));
        assert!(!matches_pattern(Path::new("file.rs"), "*.txt"));
        assert!(!matches_pattern(Path::new("txtfile"), "*.txt"));
    }

    #[test]
    fn test_matches_pattern_prefix() {
        assert!(matches_pattern(Path::new("temp_file"), "temp*"));
        assert!(matches_pattern(Path::new("temporary"), "temp*"));
        assert!(matches_pattern(Path::new("dir/temp_data"), "temp*"));
        assert!(!matches_pattern(Path::new("file_temp"), "temp*"));
        assert!(!matches_pattern(Path::new("main.rs"), "temp*"));
    }

    #[test]
    fn test_matches_pattern_component_match() {
        // Pattern should match any component in the path
        assert!(matches_pattern(Path::new("src/.git/config"), ".git"));
        assert!(matches_pattern(Path::new("a/b/.DS_Store"), ".DS_Store"));
        assert!(matches_pattern(
            Path::new("node_modules/pkg/index.js"),
            "node_modules"
        ));
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
    fn test_should_skip_hidden_files() {
        let config = CreationConfig::default();
        assert!(should_skip(Path::new(".gitignore"), &config));
        assert!(should_skip(Path::new(".env"), &config));
    }

    #[test]
    fn test_should_skip_include_hidden() {
        let config = CreationConfig::default().with_include_hidden(true);
        assert!(!should_skip(Path::new(".gitignore"), &config));
        assert!(!should_skip(Path::new(".env"), &config));
    }

    #[test]
    fn test_should_skip_excluded_patterns() {
        let config = CreationConfig::default();
        // Default patterns: .git, .DS_Store, *.tmp
        assert!(should_skip(Path::new(".git"), &config));
        assert!(should_skip(Path::new(".DS_Store"), &config));
        assert!(should_skip(Path::new("file.tmp"), &config));
    }

    #[test]
    fn test_should_skip_normal_files() {
        let config = CreationConfig::default();
        assert!(!should_skip(Path::new("main.rs"), &config));
        assert!(!should_skip(Path::new("README.md"), &config));
        assert!(!should_skip(Path::new("src/lib.rs"), &config));
    }

    #[test]
    fn test_should_skip_combines_rules() {
        let config = CreationConfig::default()
            .with_exclude_patterns(vec!["*.log".to_string(), "temp*".to_string()])
            .with_include_hidden(false);

        // Hidden file
        assert!(should_skip(Path::new(".hidden"), &config));

        // Matches exclude pattern
        assert!(should_skip(Path::new("debug.log"), &config));
        assert!(should_skip(Path::new("temp_file"), &config));

        // Normal file
        assert!(!should_skip(Path::new("main.rs"), &config));
    }

    #[test]
    fn test_pattern_matches_exact() {
        assert!(pattern_matches("test", "test"));
        assert!(pattern_matches(".git", ".git"));
        assert!(!pattern_matches("test1", "test"));
    }

    #[test]
    fn test_pattern_matches_prefix_wildcard() {
        assert!(pattern_matches("test", "test*"));
        assert!(pattern_matches("testing", "test*"));
        assert!(pattern_matches("test123", "test*"));
        assert!(!pattern_matches("atest", "test*"));
    }

    #[test]
    fn test_pattern_matches_suffix_wildcard() {
        assert!(pattern_matches("test.txt", "*.txt"));
        assert!(pattern_matches(".txt", "*.txt"));
        assert!(!pattern_matches("txt", "*.txt"));
        assert!(!pattern_matches("test.rs", "*.txt"));
    }
}
