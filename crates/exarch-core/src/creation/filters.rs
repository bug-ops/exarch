//! Path filtering logic for archive creation.
//!
//! This module provides utilities for filtering files during archive creation
//! based on patterns, hidden file rules, and size constraints.

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;
use crate::SkipKind;
use crate::Violation;
use crate::creation::config::CreationConfig;
use crate::security::boundary::MAX_CONFIG_ENTRY_LENGTH;
use std::fmt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

/// A parsed exclude rule, built once when the pattern is set.
///
/// Four shapes exist. The first three name one path component and match any
/// component of an entry's archive path; `Path` names a relative path and
/// matches it together with everything below it:
///
/// | Pattern text | Rule |
/// |---|---|
/// | `.git` | a component equal to `.git` |
/// | `temp*` | a component starting with `temp` |
/// | `*.tmp` | a component ending with `.tmp` |
/// | `build/out` | the path `build/out` and its subtree |
///
/// Matching uses the entry's archive path (after `strip_prefix` and the
/// multi-source naming), the name `list` shows, never the ancestors of a
/// source directory. Any other shape, such as `*.m*`, `a*b`, `**/x`, a bare
/// `*`, a separator combined with `*` (`build/*`, write `build`), `..` or an
/// absolute path, is refused when parsed instead of silently never matching.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::ExcludePattern;
/// use std::path::Path;
///
/// let tmp = ExcludePattern::try_from("*.tmp")?;
/// assert!(tmp.matches(Path::new("cache/a.tmp")));
/// assert!(!tmp.matches(Path::new("cache/a.txt")));
///
/// let out = ExcludePattern::try_from("build/out")?;
/// assert!(out.matches(Path::new("build/out/bin/app")));
/// assert!(!out.matches(Path::new("src/build/out")));
///
/// assert!(ExcludePattern::try_from("*.m*").is_err());
/// assert!(ExcludePattern::try_from("build/*").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExcludePattern {
    /// A component equal to `name`.
    #[non_exhaustive]
    Exact {
        /// The component name.
        name: String,
    },

    /// A component starting with `prefix` (`prefix*`).
    #[non_exhaustive]
    Prefix {
        /// The leading text.
        prefix: String,
    },

    /// A component ending with `suffix` (`*suffix`).
    #[non_exhaustive]
    Suffix {
        /// The trailing text.
        suffix: String,
    },

    /// A relative path and its subtree.
    #[non_exhaustive]
    Path {
        /// The path, built from normal components only.
        relative: PathBuf,
    },
}

impl ExcludePattern {
    const SETTING: ConfigSetting = ConfigSetting::ExcludePattern;

    pub(crate) fn exact(name: &str) -> Self {
        Self::Exact { name: name.into() }
    }

    pub(crate) fn suffix(suffix: &str) -> Self {
        Self::Suffix {
            suffix: suffix.into(),
        }
    }

    /// Whether this rule excludes the entry at `archive_path`.
    #[must_use]
    pub fn matches(&self, archive_path: &Path) -> bool {
        match self {
            Self::Exact { name } => any_component(archive_path, |c| c == name),
            Self::Prefix { prefix } => any_component(archive_path, |c| c.starts_with(prefix)),
            Self::Suffix { suffix } => any_component(archive_path, |c| c.ends_with(suffix)),
            Self::Path { relative } => archive_path.starts_with(relative),
        }
    }
}

fn any_component(path: &Path, matches: impl Fn(&str) -> bool) -> bool {
    path.components()
        .any(|component| component.as_os_str().to_str().is_some_and(&matches))
}

fn refuse(problem: ConfigProblem) -> ArchiveError {
    ArchiveError::InvalidConfiguration {
        setting: ExcludePattern::SETTING,
        problem,
    }
}

fn is_separator(c: char) -> bool {
    matches!(c, '/' | '\\')
}

impl TryFrom<&str> for ExcludePattern {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for an empty pattern, one
    /// with a null byte or over [`MAX_CONFIG_ENTRY_LENGTH`] bytes, `.` or `..`
    /// as a component, an absolute path, or a shape the matcher does not
    /// support: more than one `*`, a bare `*`, a `*` that is neither first
    /// nor last, or a `*` next to a path separator.
    fn try_from(text: &str) -> Result<Self> {
        if text.len() > MAX_CONFIG_ENTRY_LENGTH {
            return Err(refuse(ConfigProblem::TooLong {
                max: MAX_CONFIG_ENTRY_LENGTH,
                got: text.len(),
            }));
        }
        if text.contains('\0') {
            return Err(refuse(ConfigProblem::ContainsNul));
        }
        let has_separator = text.contains(is_separator);
        let wildcards = text.matches('*').count();
        if has_separator && wildcards > 0 {
            return Err(refuse(ConfigProblem::NotSupported));
        }
        if has_separator {
            return parse_path(text);
        }
        parse_component(text, wildcards)
    }
}

fn parse_component(text: &str, wildcards: usize) -> Result<ExcludePattern> {
    if text.is_empty() {
        return Err(refuse(ConfigProblem::Empty));
    }
    if text == "." || text == ".." {
        return Err(refuse(ConfigProblem::DotEntry));
    }
    match (wildcards, text.strip_prefix('*'), text.strip_suffix('*')) {
        (0, ..) => Ok(ExcludePattern::exact(text)),
        (1, Some(suffix), _) if !suffix.is_empty() => Ok(ExcludePattern::suffix(suffix)),
        (1, _, Some(prefix)) if !prefix.is_empty() => Ok(ExcludePattern::Prefix {
            prefix: prefix.into(),
        }),
        _ => Err(refuse(ConfigProblem::NotSupported)),
    }
}

fn parse_path(text: &str) -> Result<ExcludePattern> {
    if text.starts_with(is_separator) || Path::new(text).has_root() {
        return Err(refuse(ConfigProblem::NotSupported));
    }
    let mut relative = PathBuf::new();
    for segment in text
        .split(is_separator)
        .filter(|s| !s.is_empty() && *s != ".")
    {
        if segment == ".." {
            return Err(refuse(ConfigProblem::DotEntry));
        }
        relative.push(segment);
    }
    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(refuse(ConfigProblem::NotSupported));
    }
    if relative.as_os_str().is_empty() {
        return Err(refuse(ConfigProblem::Empty));
    }
    Ok(ExcludePattern::Path { relative })
}

impl std::str::FromStr for ExcludePattern {
    type Err = ArchiveError;

    fn from_str(text: &str) -> Result<Self> {
        Self::try_from(text)
    }
}

impl fmt::Display for ExcludePattern {
    /// Writes the pattern text it was parsed from, normalized.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact { name } => f.write_str(name),
            Self::Prefix { prefix } => write!(f, "{prefix}*"),
            Self::Suffix { suffix } => write!(f, "*{suffix}"),
            Self::Path { relative } => write!(f, "{}", relative.display()),
        }
    }
}

/// Returns why the entry at `archive_path` is left out of the archive, or
/// `None` when it is kept.
///
/// An entry is left out when it is hidden and `include_hidden` is false, or
/// when it matches an exclude pattern. The size limit is checked separately,
/// where the size is known.
///
/// # Examples
///
/// ```
/// use exarch_core::SkipKind;
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::filters;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// assert_eq!(
///     filters::skip_reason(Path::new(".gitignore"), &config),
///     Some(SkipKind::Hidden)
/// );
/// assert_eq!(
///     filters::skip_reason(Path::new("a.tmp"), &config),
///     Some(SkipKind::Excluded)
/// );
/// assert_eq!(filters::skip_reason(Path::new("main.rs"), &config), None);
/// ```
#[must_use]
pub fn skip_reason(archive_path: &Path, config: &CreationConfig) -> Option<SkipKind> {
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

    fn pattern(text: &str) -> ExcludePattern {
        ExcludePattern::try_from(text).unwrap()
    }

    /// The matcher this module had before patterns were parsed: every
    /// component of the full path, then the whole path string.
    fn legacy_matches(path: &Path, pattern: &str) -> bool {
        let one = |s: &str| {
            pattern == s
                || pattern
                    .strip_suffix('*')
                    .map(|prefix| s.starts_with(prefix))
                    .or_else(|| pattern.strip_prefix('*').map(|suffix| s.ends_with(suffix)))
                    .unwrap_or(false)
        };
        path.components()
            .any(|c| c.as_os_str().to_str().is_some_and(one))
            || path.to_str().is_some_and(one)
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
    fn parses_each_supported_shape() {
        assert_eq!(pattern(".git"), ExcludePattern::exact(".git"));
        assert_eq!(pattern("*.tmp"), ExcludePattern::suffix(".tmp"));
        assert_eq!(
            pattern("temp*"),
            ExcludePattern::Prefix {
                prefix: "temp".into()
            }
        );
        assert_eq!(
            pattern("build/out"),
            ExcludePattern::Path {
                relative: PathBuf::from("build/out")
            }
        );
        assert_eq!(
            pattern("target/"),
            ExcludePattern::Path {
                relative: PathBuf::from("target")
            },
            "a trailing separator anchors the name at the archive root"
        );
        assert_eq!(pattern("./a\\b"), pattern("a/b"));
    }

    #[test]
    fn refuses_unsupported_shapes() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        for text in [
            "", "*", "**", "*.m*", "a*b", "**/x", "build/*", "*/x", "a/*/b", "..", ".", "../x",
            "a/../b", "/abs", "\\abs", "bad\0nul", "./", "/", &long,
        ] {
            let result = ExcludePattern::try_from(text);
            assert!(
                matches!(
                    result,
                    Err(ArchiveError::InvalidConfiguration {
                        setting: ConfigSetting::ExcludePattern,
                        ..
                    })
                ),
                "{text:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn refusal_names_the_problem() {
        let problem = |text: &str| match ExcludePattern::try_from(text) {
            Err(ArchiveError::InvalidConfiguration { problem, .. }) => problem,
            other => panic!("{text:?} must be refused, got {other:?}"),
        };
        assert_eq!(problem(""), ConfigProblem::Empty);
        assert_eq!(problem("bad\0"), ConfigProblem::ContainsNul);
        assert_eq!(problem(".."), ConfigProblem::DotEntry);
        assert_eq!(problem("a/../b"), ConfigProblem::DotEntry);
        assert_eq!(problem("*.m*"), ConfigProblem::NotSupported);
        assert_eq!(problem("build/*"), ConfigProblem::NotSupported);
        assert_eq!(problem("/abs"), ConfigProblem::NotSupported);
    }

    #[test]
    fn component_patterns_match_any_component() {
        assert!(pattern(".git").matches(Path::new("src/.git/config")));
        assert!(!pattern(".git").matches(Path::new(".github")));
        assert!(pattern("*.txt").matches(Path::new("dir/file.txt")));
        assert!(!pattern("*.txt").matches(Path::new("txtfile")));
        assert!(pattern("temp*").matches(Path::new("dir/temp_data")));
        assert!(!pattern("temp*").matches(Path::new("file_temp")));
    }

    #[test]
    fn path_pattern_matches_the_subtree_from_the_start() {
        let out = pattern("build/out");
        assert!(out.matches(Path::new("build/out")));
        assert!(out.matches(Path::new("build/out/a/b")));
        assert!(!out.matches(Path::new("build/outside")));
        assert!(!out.matches(Path::new("x/build/out")));
        assert!(!out.matches(Path::new("build")));
    }

    #[test]
    fn display_round_trips() {
        for text in [".git", "*.tmp", "temp*", "build/out"] {
            assert_eq!(pattern(text).to_string(), text);
        }
    }

    /// The old matcher walked the whole source path, so the ancestors of the
    /// root leaked into the match (#916). For every shape it accepted that the
    /// new parser also accepts, the new matcher selects the same entries when
    /// the root does not match.
    #[test]
    fn agrees_with_the_legacy_matcher_under_a_non_matching_root() {
        let relatives = [
            "a.txt",
            "notes.md",
            ".git",
            ".git/config",
            ".DS_Store",
            "x/y.tmp",
            "temp_file",
            "dir/temp_data",
            "file_temp",
            "src/main.rs",
            ".github",
            "txtfile",
        ];
        for text in [
            ".git",
            ".DS_Store",
            "*.tmp",
            "*.txt",
            "temp*",
            "node_modules",
        ] {
            let new = pattern(text);
            for relative in relatives {
                let old = legacy_matches(&Path::new("srcroot").join(relative), text);
                assert_eq!(
                    new.matches(Path::new(relative)),
                    old,
                    "{text:?} vs {relative:?}"
                );
            }
        }
    }

    #[test]
    fn ancestors_of_the_root_no_longer_match() {
        // `job.tmp/a.txt` as the old matcher saw it from outside the root.
        assert!(legacy_matches(Path::new("job.tmp/a.txt"), "*.tmp"));
        assert!(!pattern("*.tmp").matches(Path::new("a.txt")));
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
