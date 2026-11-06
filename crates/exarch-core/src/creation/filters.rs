//! Path filtering logic for archive creation.
//!
//! This module provides utilities for filtering files during archive creation
//! based on patterns, hidden file rules, and size constraints.

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::ExcludeRefusal;
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
/// source directory. That path does not start with the source directory's own
/// name, so a pattern such as `src/build` for a source `src` matches
/// nothing; write `build`. A non-UTF-8 component is matched by its raw bytes.
/// There is no escaping, so a name holding `?`, `[`, `]`, `{`, `}`, `!` or a
/// comma, or one with leading or trailing whitespace, cannot be excluded by
/// name and is refused. Any other shape, such as `*.m*`, `a*b`, `**/x`, a bare
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
            Self::Exact { name } => any_component(archive_path, |c| c == name.as_bytes()),
            Self::Prefix { prefix } => {
                any_component(archive_path, |c| c.starts_with(prefix.as_bytes()))
            }
            Self::Suffix { suffix } => {
                any_component(archive_path, |c| c.ends_with(suffix.as_bytes()))
            }
            Self::Path { relative } => archive_path.starts_with(relative),
        }
    }
}

fn any_component(path: &Path, matches: impl Fn(&[u8]) -> bool) -> bool {
    path.components()
        .any(|component| matches(component.as_os_str().as_encoded_bytes()))
}

fn refuse(setting: ConfigSetting, text: &str, reason: ExcludeRefusal) -> ArchiveError {
    let end = text.floor_char_boundary(MAX_CONFIG_ENTRY_LENGTH);
    ArchiveError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::ExcludePatternRefused {
            pattern: text.get(..end).unwrap_or(text).to_owned(),
            reason,
        },
    }
}

fn is_separator(c: char) -> bool {
    matches!(c, '/' | '\\')
}

impl ExcludePattern {
    /// Parses `text`, naming `setting` in the refusal.
    ///
    /// One grammar serves every use of a pattern: pass
    /// [`ConfigSetting::ExcludePattern`] for creation,
    /// [`ConfigSetting::EntryInclude`] or [`ConfigSetting::EntryExclude`] for
    /// extraction. [`TryFrom<&str>`] is the creation form.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting`, with
    /// [`ConfigProblem::ExcludePatternRefused`], which names the pattern and an
    /// [`ExcludeRefusal`], for: an empty pattern, one over
    /// [`MAX_CONFIG_ENTRY_LENGTH`] bytes or with a null byte, leading or
    /// trailing whitespace, a comma, any of `?`, `[`, `]`, `{`, `}` and `!`
    /// (they are not glob syntax here, so they would match literally and
    /// silently exclude nothing), `.` or `..` as a component, an absolute
    /// path, or a `*` shape other than `name*` and `*name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ConfigSetting;
    /// use exarch_core::ExcludePattern;
    ///
    /// let pattern = ExcludePattern::parse_for(ConfigSetting::EntryInclude, "docs/api")?;
    /// assert_eq!(pattern.to_string(), "docs/api");
    /// assert!(ExcludePattern::parse_for(ConfigSetting::EntryInclude, "**/x").is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn parse_for(setting: ConfigSetting, text: &str) -> Result<Self> {
        let is_blank = |c: char| c.is_ascii_whitespace() || c.is_ascii_control();
        let refuse = |reason| refuse(setting, text, reason);
        if text.len() > MAX_CONFIG_ENTRY_LENGTH {
            return Err(refuse(ExcludeRefusal::TooLong));
        }
        if text.contains('\0') {
            return Err(refuse(ExcludeRefusal::ContainsNul));
        }
        if text.is_empty() {
            return Err(refuse(ExcludeRefusal::Empty));
        }
        if text.starts_with(is_blank) || text.ends_with(is_blank) {
            return Err(refuse(ExcludeRefusal::PaddedWithBlank));
        }
        if text.contains(',') {
            return Err(refuse(ExcludeRefusal::ContainsComma));
        }
        if text.contains(['?', '[', ']', '{', '}', '!']) {
            return Err(refuse(ExcludeRefusal::GlobMetacharacter));
        }
        let has_separator = text.contains(is_separator);
        let wildcards = text.matches('*').count();
        if has_separator && wildcards > 0 {
            return Err(refuse(ExcludeRefusal::WildcardWithSeparator));
        }
        if has_separator {
            return parse_path(setting, text);
        }
        parse_component(setting, text, wildcards)
    }
}

impl TryFrom<&str> for ExcludePattern {
    type Error = ArchiveError;

    /// Parses a creation exclude pattern; see [`ExcludePattern::parse_for`].
    ///
    /// # Errors
    ///
    /// Refusals name [`ConfigSetting::ExcludePattern`].
    fn try_from(text: &str) -> Result<Self> {
        Self::parse_for(ConfigSetting::ExcludePattern, text)
    }
}

fn parse_component(setting: ConfigSetting, text: &str, wildcards: usize) -> Result<ExcludePattern> {
    if text == "." || text == ".." {
        return Err(refuse(setting, text, ExcludeRefusal::DotEntry));
    }
    match (wildcards, text.strip_prefix('*'), text.strip_suffix('*')) {
        (0, ..) => Ok(ExcludePattern::exact(text)),
        (1, Some(suffix), _) if !suffix.is_empty() => Ok(ExcludePattern::suffix(suffix)),
        (1, _, Some(prefix)) if !prefix.is_empty() => Ok(ExcludePattern::Prefix {
            prefix: prefix.into(),
        }),
        _ => Err(refuse(setting, text, ExcludeRefusal::UnsupportedWildcard)),
    }
}

fn parse_path(setting: ConfigSetting, text: &str) -> Result<ExcludePattern> {
    if text.starts_with(is_separator) || Path::new(text).has_root() {
        return Err(refuse(setting, text, ExcludeRefusal::Absolute));
    }
    let mut relative = PathBuf::new();
    for segment in text
        .split(is_separator)
        .filter(|s| !s.is_empty() && *s != ".")
    {
        if segment == ".." {
            return Err(refuse(setting, text, ExcludeRefusal::DotEntry));
        }
        relative.push(segment);
    }
    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(refuse(setting, text, ExcludeRefusal::Absolute));
    }
    if relative.is_empty() {
        return Err(refuse(setting, text, ExcludeRefusal::Empty));
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
    /// Writes the pattern text it was parsed from, normalized; a path pattern
    /// always uses `/` between components, whatever the host separator.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact { name } => f.write_str(name),
            Self::Prefix { prefix } => write!(f, "{prefix}*"),
            Self::Suffix { suffix } => write!(f, "*{suffix}"),
            Self::Path { relative } => {
                let mut components = relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy());
                if let Some(first) = components.next() {
                    f.write_str(&first)?;
                }
                components.try_for_each(|component| write!(f, "/{component}"))
            }
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

    fn refusal(text: &str) -> (String, ExcludeRefusal) {
        match ExcludePattern::try_from(text) {
            Err(ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::ExcludePattern,
                problem: ConfigProblem::ExcludePatternRefused { pattern, reason },
            }) => (pattern, reason),
            other => panic!("{text:?} must be refused with a typed reason, got {other:?}"),
        }
    }

    #[test]
    fn every_refused_shape_names_the_pattern_and_a_typed_reason() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let cases: [(&str, ExcludeRefusal); 29] = [
            ("", ExcludeRefusal::Empty),
            ("./", ExcludeRefusal::Empty),
            ("bad\0nul", ExcludeRefusal::ContainsNul),
            (&long, ExcludeRefusal::TooLong),
            ("..", ExcludeRefusal::DotEntry),
            (".", ExcludeRefusal::DotEntry),
            ("../x", ExcludeRefusal::DotEntry),
            ("a/../b", ExcludeRefusal::DotEntry),
            ("/abs", ExcludeRefusal::Absolute),
            ("\\abs", ExcludeRefusal::Absolute),
            ("/", ExcludeRefusal::Absolute),
            ("*", ExcludeRefusal::UnsupportedWildcard),
            ("**", ExcludeRefusal::UnsupportedWildcard),
            ("*.m*", ExcludeRefusal::UnsupportedWildcard),
            ("a*b", ExcludeRefusal::UnsupportedWildcard),
            ("**/x", ExcludeRefusal::WildcardWithSeparator),
            ("build/*", ExcludeRefusal::WildcardWithSeparator),
            ("*/x", ExcludeRefusal::WildcardWithSeparator),
            ("?.txt", ExcludeRefusal::GlobMetacharacter),
            ("[a", ExcludeRefusal::GlobMetacharacter),
            ("a]", ExcludeRefusal::GlobMetacharacter),
            ("{a}", ExcludeRefusal::GlobMetacharacter),
            ("!a.txt", ExcludeRefusal::GlobMetacharacter),
            ("dir/a?", ExcludeRefusal::GlobMetacharacter),
            (" .env", ExcludeRefusal::PaddedWithBlank),
            (".env ", ExcludeRefusal::PaddedWithBlank),
            ("a\t", ExcludeRefusal::PaddedWithBlank),
            ("a,b", ExcludeRefusal::ContainsComma),
            ("a/b,c", ExcludeRefusal::ContainsComma),
        ];
        for (text, expected) in cases {
            let (pattern, reason) = refusal(text);
            assert_eq!(reason, expected, "{text:?}");
            assert_eq!(pattern, text.get(..MAX_CONFIG_ENTRY_LENGTH).unwrap_or(text));
        }
    }

    #[test]
    fn a_refusal_message_quotes_the_pattern() {
        let err = ExcludePattern::try_from("?.txt").unwrap_err();
        let ArchiveError::InvalidConfiguration { setting, problem } = err else {
            panic!("expected an invalid configuration");
        };
        let message = setting.describe(&problem);
        assert!(
            message.starts_with("exclude pattern \"?.txt\" "),
            "{message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_components_match_by_their_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let key = Path::new(OsStr::from_bytes(b"dir/\xff.key"));
        assert!(pattern("*.key").matches(key));
        assert!(pattern("dir").matches(key));
        assert!(!pattern("*.pem").matches(key));
        assert!(pattern("dir/").matches(key));

        let hidden = Path::new(OsStr::from_bytes(b".\xff"));
        assert!(is_hidden(hidden));
        let config = CreationConfig::default();
        assert_eq!(skip_reason(hidden, &config), Some(SkipKind::Hidden));
        let excluded = Path::new(OsStr::from_bytes(b"a/\xfe.tmp"));
        assert_eq!(skip_reason(excluded, &config), Some(SkipKind::Excluded));
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
