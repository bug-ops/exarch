//! Validated `SecurityConfig` list entries.
//!
//! An allowlisted extension and a banned path component each have a rule for
//! what a usable value is. These types parse a raw string once, so every front
//! end (core, CLI, Python, Node) shares one constructor and a value that could
//! never match is refused instead of silently turning extraction into a no-op.

use std::cell::OnceCell;
use std::fmt;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;
use crate::security::boundary::MAX_CONFIG_ENTRY_LENGTH;
use crate::security::fs_view::decomposed_fold;

fn invalid(setting: ConfigSetting, problem: ConfigProblem) -> ArchiveError {
    ArchiveError::InvalidConfiguration { setting, problem }
}

fn check_length_and_nul(value: &str, setting: ConfigSetting) -> Result<()> {
    if value.len() > MAX_CONFIG_ENTRY_LENGTH {
        return Err(invalid(
            setting,
            ConfigProblem::TooLong {
                max: MAX_CONFIG_ENTRY_LENGTH,
                got: value.len(),
            },
        ));
    }
    if value.contains('\0') {
        return Err(invalid(setting, ConfigProblem::ContainsNul));
    }
    Ok(())
}

fn has_separator(value: &str) -> bool {
    value.contains(['/', '\\'])
}

/// A file extension without its leading dot, ASCII-lowercased.
///
/// Built only through [`TryFrom<&str>`]: one leading `.` is stripped and the
/// rest is lowercased. The value is never empty and holds no ASCII whitespace
/// or control character, path separator or inner `.` (`Path::extension` never
/// yields one, so such an entry could never match), and is at most
/// [`MAX_CONFIG_ENTRY_LENGTH`] bytes.
///
/// # Examples
///
/// ```
/// use exarch_core::Extension;
///
/// assert_eq!(Extension::try_from(".TXT")?.as_str(), "txt");
/// assert!(Extension::try_from("tar.gz").is_err());
/// assert!(Extension::try_from(" gz").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extension(Box<str>);

impl Extension {
    const SETTING: ConfigSetting = ConfigSetting::AllowedExtension;

    /// The normalized extension, without a leading dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `extension`, as `Path::extension` yields it, is this extension
    /// ignoring ASCII case.
    #[must_use]
    pub fn matches(&self, extension: &str) -> bool {
        self.0.eq_ignore_ascii_case(extension)
    }
}

impl TryFrom<&str> for Extension {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for an empty value (after
    /// the leading dot), a null byte, ASCII whitespace or control character,
    /// path separator, inner `.`, or a value over [`MAX_CONFIG_ENTRY_LENGTH`]
    /// bytes.
    fn try_from(value: &str) -> Result<Self> {
        check_length_and_nul(value, Self::SETTING)?;
        let name = value.trim_prefix('.');
        if name.is_empty() {
            return Err(invalid(Self::SETTING, ConfigProblem::Empty));
        }
        if name
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return Err(invalid(Self::SETTING, ConfigProblem::BlankOrControl));
        }
        if has_separator(name) {
            return Err(invalid(Self::SETTING, ConfigProblem::ContainsSeparator));
        }
        if name.contains('.') {
            return Err(invalid(Self::SETTING, ConfigProblem::InnerDot));
        }
        Ok(Self(name.to_ascii_lowercase().into_boxed_str()))
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A non-empty list of allowed [`Extension`]s.
///
/// The only way to build one is [`Extensions::new`], which refuses an empty
/// list, so an allowlist that admits nothing cannot be mistaken for "no
/// allowlist".
///
/// # Examples
///
/// ```
/// use exarch_core::Extension;
/// use exarch_core::Extensions;
///
/// let extensions = Extensions::new(vec![Extension::try_from("txt")?])?;
/// assert!(extensions.matches("TXT"));
/// assert!(Extensions::new(Vec::new()).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    /// Wraps a list of extensions.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming
    /// [`ConfigSetting::AllowedExtension`] with [`ConfigProblem::Empty`] for an
    /// empty list.
    pub fn new(extensions: Vec<Extension>) -> Result<Self> {
        if extensions.is_empty() {
            return Err(invalid(Extension::SETTING, ConfigProblem::Empty));
        }
        Ok(Self(extensions))
    }

    /// The extensions, in the order they were given.
    #[must_use]
    pub fn as_slice(&self) -> &[Extension] {
        &self.0
    }

    /// Whether `extension`, as `Path::extension` yields it, is one of them.
    #[must_use]
    pub fn matches(&self, extension: &str) -> bool {
        self.0.iter().any(|allowed| allowed.matches(extension))
    }

    fn pushed(mut self, extension: Extension) -> Self {
        self.0.push(extension);
        self
    }
}

/// Which file extensions extraction admits.
///
/// [`Any`](Self::Any) is the default and admits every file, with or without an
/// extension. [`Only`](Self::Only) admits just the listed extensions and skips
/// files without one. The two states are variants, so an allowlist that came up
/// empty is refused by [`ExtensionFilter::only`] instead of silently admitting
/// everything.
///
/// # Examples
///
/// ```
/// use exarch_core::Extension;
/// use exarch_core::ExtensionFilter;
///
/// let filter = ExtensionFilter::only(vec![Extension::try_from("txt")?])?;
/// assert!(filter.allows(Some("txt")));
/// assert!(!filter.allows(None));
/// assert!(ExtensionFilter::Any.allows(None));
/// assert!(ExtensionFilter::only(Vec::new()).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionFilter {
    /// Every file is extracted.
    #[default]
    Any,
    /// Only files with one of these extensions are extracted.
    Only(Extensions),
}

impl ExtensionFilter {
    /// An allowlist of `extensions`.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] with
    /// [`ConfigProblem::Empty`] for an empty list.
    pub fn only(extensions: Vec<Extension>) -> Result<Self> {
        Extensions::new(extensions).map(Self::Only)
    }

    /// Whether every file is admitted.
    #[must_use]
    pub const fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// The allowlist, or `None` when every file is admitted.
    #[must_use]
    pub const fn as_only(&self) -> Option<&Extensions> {
        match self {
            Self::Any => None,
            Self::Only(extensions) => Some(extensions),
        }
    }

    /// Whether a file whose extension is `extension` is admitted. A file
    /// without an extension is admitted only by [`Any`](Self::Any).
    #[must_use]
    pub fn allows(&self, extension: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Only(allowed) => extension.is_some_and(|ext| allowed.matches(ext)),
        }
    }

    /// This filter with `extension` admitted too; [`Any`](Self::Any) becomes an
    /// allowlist of just that extension.
    #[must_use]
    pub fn with_added(self, extension: Extension) -> Self {
        match self {
            Self::Any => Self::Only(Extensions(vec![extension])),
            Self::Only(allowed) => Self::Only(allowed.pushed(extension)),
        }
    }
}

/// One normal path component that archive entries may not contain.
///
/// Built only through [`TryFrom<&str>`]. The value is never empty, holds no
/// null byte or path separator, is not `.` or `..`, neither starts nor ends
/// with an ASCII whitespace or control character, and is at most
/// [`MAX_CONFIG_ENTRY_LENGTH`] bytes, so it can equal a single component.
/// Matching compares names after canonical decomposition (NFD) and a
/// per-character upper, lower, upper case mapping. That fold equates at least
/// every pair of names full case folding equates, and a few more, so a ban
/// holds on filesystems that fold names either way. Code points that HFS+
/// ignores when it compares names (U+200C to U+200F, U+202A to U+202E,
/// U+206A to U+206F and U+FEFF) are dropped first.
///
/// # Examples
///
/// ```
/// use exarch_core::PathComponentName;
///
/// let banned = PathComponentName::try_from(".git")?;
/// assert!(banned.matches(".GIT"));
/// assert!(PathComponentName::try_from("a/b").is_err());
/// assert!(PathComponentName::try_from("..").is_err());
/// assert!(PathComponentName::try_from(" .git").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathComponentName {
    name: Box<str>,
    folded: Box<str>,
}

impl PathComponentName {
    const SETTING: ConfigSetting = ConfigSetting::BannedPathComponent;

    /// The component name as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Whether `component` equals this name after canonical decomposition and
    /// the case mapping described on [`PathComponentName`], so a ban holds on
    /// case-insensitive filesystems.
    #[must_use]
    pub fn matches(&self, component: &str) -> bool {
        self.matches_folding_once(component, &OnceCell::new())
    }

    /// Like [`matches`](Self::matches), but computes the fold of `component`
    /// at most once across calls that share `fold`.
    pub(crate) fn matches_folding_once(&self, component: &str, fold: &OnceCell<String>) -> bool {
        if component.is_ascii() && self.name.is_ascii() {
            return self.name.eq_ignore_ascii_case(component);
        }
        *self.folded == **fold.get_or_init(|| fold_name(component))
    }
}

impl TryFrom<&str> for PathComponentName {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for an empty value, one
    /// with leading or trailing ASCII whitespace or control characters, a null
    /// byte, a path separator, `.`, `..`, a value made only of code points
    /// that name comparison ignores, or a value over
    /// [`MAX_CONFIG_ENTRY_LENGTH`] bytes.
    fn try_from(value: &str) -> Result<Self> {
        check_length_and_nul(value, Self::SETTING)?;
        if value.is_empty() {
            return Err(invalid(Self::SETTING, ConfigProblem::Empty));
        }
        let is_blank = |c: char| c.is_ascii_whitespace() || c.is_ascii_control();
        if value.starts_with(is_blank) || value.ends_with(is_blank) {
            return Err(invalid(Self::SETTING, ConfigProblem::PaddedWithBlank));
        }
        if has_separator(value) {
            return Err(invalid(Self::SETTING, ConfigProblem::ContainsSeparator));
        }
        if value == "." || value == ".." {
            return Err(invalid(Self::SETTING, ConfigProblem::DotEntry));
        }
        let folded = fold_name(value);
        if folded.is_empty() {
            return Err(invalid(Self::SETTING, ConfigProblem::OnlyIgnoredCharacters));
        }
        Ok(Self {
            name: value.into(),
            folded: folded.into(),
        })
    }
}

/// Code points HFS+ drops when it compares names.
const fn is_ignored_by_compare(c: char) -> bool {
    matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
}

/// The key two names share when a case-insensitive filesystem treats them as
/// one name.
fn fold_name(name: &str) -> String {
    if name.chars().any(is_ignored_by_compare) {
        decomposed_fold(&name.replace(is_ignored_by_compare, ""))
    } else {
        decomposed_fold(name)
    }
}

impl fmt::Display for PathComponentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    #[test]
    fn extension_strips_one_leading_dot_and_lowercases() {
        for (raw, normalized) in [
            ("txt", "txt"),
            (".txt", "txt"),
            (".TXT", "txt"),
            ("Gz", "gz"),
        ] {
            assert_eq!(Extension::try_from(raw).unwrap().as_str(), normalized);
        }
    }

    #[test]
    fn extension_matches_ignoring_ascii_case_on_the_path_side() {
        let txt = Extension::try_from("txt").unwrap();
        assert!(txt.matches("TXT"));
        assert!(txt.matches("txt"));
        assert!(!txt.matches("tx"));
    }

    #[test]
    fn extension_refuses_unusable_values() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        for raw in [
            "",
            ".",
            "..txt",
            "tar.gz",
            "a/b",
            "a\\b",
            " gz",
            "gz ",
            "g z",
            "g\tz",
            "bad\0ext",
            "g\u{7f}z",
            long.as_str(),
        ] {
            assert!(Extension::try_from(raw).is_err(), "{raw:?} must be refused");
        }
    }

    #[test]
    fn extension_accepts_the_maximum_length() {
        assert!(Extension::try_from("x".repeat(MAX_CONFIG_ENTRY_LENGTH).as_str()).is_ok());
    }

    #[test]
    fn extension_length_is_measured_in_bytes() {
        let multibyte = "日".repeat(100);
        let err = Extension::try_from(multibyte.as_str()).unwrap_err();
        assert!(err.to_string().contains("bytes"), "{err}");
    }

    #[test]
    fn component_keeps_its_case_and_matches_ignoring_it() {
        let git = PathComponentName::try_from(".Git").unwrap();
        assert_eq!(git.as_str(), ".Git");
        assert!(git.matches(".git"));
        assert!(!git.matches(".gitx"));
    }

    #[test]
    fn component_matches_unicode_case_fold_spellings() {
        for (name, spelled) in [
            (".ssh", ".\u{17f}sh"),
            (".ssh", ".\u{df}h"),
            (".ssh", ".\u{17f}\u{17f}h"),
            (".aws", ".aw\u{17f}"),
            (".kube", ".\u{212a}ube"),
            (".docker", ".doc\u{212a}er"),
            (".git", ".GIT"),
            (".gnupg", ".GnuPG"),
            (".env", ".ENV"),
        ] {
            let banned = PathComponentName::try_from(name).unwrap();
            assert!(banned.matches(spelled), "{spelled:?} must match {name:?}");
        }
    }

    #[test]
    fn component_matches_names_with_ignorable_code_points_inserted() {
        let banned = PathComponentName::try_from(".ssh").unwrap();
        for ignorable in [
            '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}', '\u{206a}',
            '\u{206f}', '\u{feff}',
        ] {
            let spelled = format!(".s{ignorable}sh");
            assert!(banned.matches(&spelled), "{spelled:?}");
            let leading = format!("{ignorable}.ssh{ignorable}");
            assert!(banned.matches(&leading), "{leading:?}");
        }
        assert!(!banned.matches(".s\u{200c}shx"));
        assert!(!banned.matches(".s\u{2060}sh"));

        let configured = PathComponentName::try_from("a\u{200c}b").unwrap();
        assert!(configured.matches("ab"));
        assert!(configured.matches("A\u{feff}B"));
    }

    #[test]
    fn component_matches_decomposed_spelling_of_a_non_ascii_name() {
        let banned = PathComponentName::try_from("caf\u{e9}").unwrap();
        assert!(banned.matches("cafe\u{301}"));
        assert!(banned.matches("CAFE\u{301}"));
        let decomposed = PathComponentName::try_from("cafe\u{301}").unwrap();
        assert!(decomposed.matches("caf\u{c9}"));
        assert!(!banned.matches("cafe"));
    }

    #[test]
    fn component_refuses_a_name_made_only_of_ignorable_code_points() {
        for raw in ["\u{200c}", "\u{feff}\u{200d}", "\u{202a}\u{206f}"] {
            let err = PathComponentName::try_from(raw).unwrap_err();
            assert_matches!(
                err,
                ArchiveError::InvalidConfiguration {
                    setting: ConfigSetting::BannedPathComponent,
                    problem: ConfigProblem::OnlyIgnoredCharacters
                },
                "{raw:?}"
            );
            assert_eq!(
                err.to_string(),
                "invalid configuration: banned path component must not consist only of \
                 characters that file name comparison ignores"
            );
        }
        assert!(PathComponentName::try_from("a\u{200c}").is_ok());
    }

    #[test]
    fn component_accepts_inner_spaces() {
        assert!(PathComponentName::try_from("my dir").is_ok());
    }

    #[test]
    fn component_refuses_unusable_values() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        for raw in [
            "",
            " ",
            "\t",
            " .git",
            ".git ",
            "\n.git",
            ".git\u{7f}",
            ".",
            "..",
            "a/b",
            "a\\b",
            "/",
            "bad\0",
            long.as_str(),
        ] {
            assert!(
                PathComponentName::try_from(raw).is_err(),
                "{raw:?} must be refused"
            );
        }
    }
}
