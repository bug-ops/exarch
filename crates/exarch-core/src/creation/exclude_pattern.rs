//! Glob patterns that select archive entries.
//!
//! One grammar serves `create --exclude` and the extraction include/exclude
//! lists. [`ExcludePattern`] hides its matching engine: no `globset` type
//! appears in a public signature, so the dependency can change without a
//! semver break.

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::ExcludeRefusal;
use crate::Result;
use crate::security::boundary::MAX_CONFIG_ENTRY_LENGTH;
use globset::Candidate;
use globset::ErrorKind;
use globset::GlobBuilder;
use globset::GlobSet;
use globset::GlobSetBuilder;
use std::borrow::Cow;
use std::fmt;
use std::path::Component;
use std::path::Path;

const GLOBSTAR: &str = "**";

/// What a pattern selects, independent of how it is matched.
///
/// `Eq` and `Hash` live here, so two patterns are equal exactly when they
/// select the same paths by construction (`target/` equals `./target`, but
/// `x` does not equal `./x`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Shape {
    /// Every path.
    MatchAll,
    /// One pattern segment tested against every path component, and so the
    /// subtree below a match.
    Floating(Box<str>),
    /// A `/`-joined pattern tested against the path from its start, and so the
    /// subtree below a match.
    Anchored(Box<str>),
}

#[derive(Clone)]
enum Engine {
    /// Plain comparison; exact for [`Shape::MatchAll`] and for shapes without
    /// `*`, `?` or `[` (a `*name` suffix included).
    Direct,
    Glob(GlobSet),
}

/// A glob pattern that selects archive entries, built once when the pattern
/// is set.
///
/// The same type serves `create --exclude` and the extraction include and
/// exclude lists. A pattern is tested against the entry's archive path
/// (after `strip_prefix` and the multi-source naming), the name `list` shows,
/// never the ancestors of a source directory.
///
/// # Syntax
///
/// | Element | Meaning |
/// |---|---|
/// | `*` | any run of bytes within one path component, possibly empty |
/// | `?` | exactly one byte within one component (`caf?` does not match `cafe` followed by a multi-byte letter) |
/// | `[a-c]`, `[0-9]`, `[abc]` | one byte from a positive ASCII class; a range needs both ends in `0-9`, `a-z` or `A-Z` |
/// | `**` | as a whole component: any number of components, including none |
/// | `[*]`, `[?]`, `[[]` | the literal character |
///
/// `\` is a path separator, not an escape. Matching is case-sensitive on
/// every host and works on raw bytes, so a non-UTF-8 name matches `*`. A
/// leading dot is not special.
///
/// # Meaning
///
/// A pattern without any `/` (a name) is *floating*: it matches an entry
/// when any component of its path matches, and so everything below a matching
/// directory. A pattern with a `/` anywhere, including a trailing one
/// (`target/`) or a leading `./`, is *anchored*: it matches from the start of
/// the archive path, and so the subtree below a match (`build/out` matches
/// `build/out/bin`, not `src/build/out`). Empty and `.` segments and a
/// trailing `**` are dropped, so `target/`, `./target` and `target/**` are
/// equal patterns, while `x` and `./x` are not. A pattern made only of `**`
/// matches every entry.
///
/// The path is normalized before matching: empty and `.` components are
/// ignored, so `build//out/x` matches `build/out`. A path with a root, a
/// prefix or a `..` component, or with no component, matches nothing.
///
/// # Refused syntax
///
/// A pattern that would silently mean something else is refused when parsed:
/// an empty or over-long pattern, a NUL byte, `.` or `..` as a component, an
/// absolute path, leading or trailing whitespace, a comma, a leading `!`
/// (patterns cannot negate), `{` and `}` (no alternation), `**` glued to
/// other characters (`a**b`), negated (`[!x]`), POSIX (`[[:alpha:]]`) or
/// non-ASCII classes, an unterminated class, and a class range outside
/// `0-9`, `a-z` and `A-Z`. See [`ExcludeRefusal`].
///
/// # Resources
///
/// Pattern length is bounded; the number of patterns is not. Each pattern
/// that uses `*`, `?`, `[` or `**` owns a compiled matcher whose lazily
/// grown search cache can reach 10 MiB per thread under adversarial input.
///
/// # Examples
///
/// ```
/// use exarch_core::ExcludePattern;
/// use std::path::Path;
///
/// let tmp = ExcludePattern::try_from("*.tmp")?;
/// assert!(tmp.matches(Path::new("cache/a.tmp")));
/// assert!(!tmp.matches(Path::new("cache/a.txt")));
///
/// let rs = ExcludePattern::try_from("src/**/*.rs")?;
/// assert!(rs.matches(Path::new("src/a/b/lib.rs")));
/// assert!(rs.matches(Path::new("src/lib.rs")));
/// assert!(!rs.matches(Path::new("tests/lib.rs")));
///
/// let out = ExcludePattern::try_from("build/out")?;
/// assert!(out.matches(Path::new("build/out/bin/app")));
/// assert!(!out.matches(Path::new("src/build/out")));
///
/// assert!(ExcludePattern::try_from("a{b,c}").is_err());
/// assert!(ExcludePattern::try_from("!keep").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Clone)]
pub struct ExcludePattern {
    shape: Shape,
    engine: Engine,
}

const _: () = {
    const fn auto_traits<
        T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >() {
    }
    auto_traits::<ExcludePattern>();
};

impl PartialEq for ExcludePattern {
    fn eq(&self, other: &Self) -> bool {
        self.shape == other.shape
    }
}

impl Eq for ExcludePattern {}

impl std::hash::Hash for ExcludePattern {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.shape.hash(state);
    }
}

impl fmt::Debug for ExcludePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExcludePattern({self})")
    }
}

impl ExcludePattern {
    /// A pattern naming one literal component, for the built-in defaults.
    pub(crate) fn literal_name(name: &'static str) -> Self {
        Self {
            shape: Shape::Floating(name.into()),
            engine: Engine::Direct,
        }
    }

    /// A pattern for the components ending in `suffix` (`*suffix`), for the
    /// built-in defaults.
    pub(crate) fn suffix_name(suffix: &'static str) -> Self {
        Self {
            shape: Shape::Floating(format!("*{suffix}").into()),
            engine: Engine::Direct,
        }
    }

    fn from_shape(shape: Shape, allow_direct: bool) -> std::result::Result<Self, ExcludeRefusal> {
        let engine = engine_for(&shape, allow_direct)?;
        Ok(Self { shape, engine })
    }

    /// Parses `text`, naming `setting` in the refusal.
    ///
    /// One grammar serves every use of a pattern: pass
    /// [`ConfigSetting::ExcludePattern`] for creation,
    /// [`ConfigSetting::EntryInclude`] or [`ConfigSetting::EntryExclude`] for
    /// extraction. [`TryFrom<&str>`] is the creation form. The syntax and its
    /// meaning are described on [`ExcludePattern`].
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting`, with
    /// [`ConfigProblem::ExcludePatternRefused`], which names the pattern and an
    /// [`ExcludeRefusal`] for the refused shape.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ConfigSetting;
    /// use exarch_core::ExcludePattern;
    ///
    /// let pattern = ExcludePattern::parse_for(ConfigSetting::EntryInclude, "docs/api")?;
    /// assert_eq!(pattern.to_string(), "docs/api");
    /// assert!(ExcludePattern::parse_for(ConfigSetting::EntryInclude, "a**b").is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn parse_for(setting: ConfigSetting, text: &str) -> Result<Self> {
        parse_shape(text)
            .and_then(|shape| Self::from_shape(shape, true))
            .map_err(|reason| refuse(setting, text, reason))
    }

    /// Whether this pattern selects the entry at `archive_path`.
    ///
    /// The path is normalized first (see the type docs); a path with a root,
    /// a prefix, a `..` component or no component matches nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExcludePattern;
    /// use std::path::Path;
    ///
    /// let p = ExcludePattern::try_from("build/out")?;
    /// assert!(p.matches(Path::new("build//out/./x")));
    /// assert!(!p.matches(Path::new("build/../out")));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    pub fn matches(&self, archive_path: &Path) -> bool {
        normalized(archive_path).is_some_and(|path| self.matches_normalized(&path))
    }

    fn matches_normalized(&self, path: &[u8]) -> bool {
        match &self.engine {
            Engine::Glob(set) => set.is_match_candidate(&Candidate::from_bytes(path)),
            Engine::Direct => match &self.shape {
                Shape::MatchAll => true,
                Shape::Floating(pattern) => {
                    let pattern = pattern.as_bytes();
                    path.split(|b| *b == b'/').any(|component| {
                        pattern
                            .strip_prefix(b"*")
                            .map_or(component == pattern, |suffix| component.ends_with(suffix))
                    })
                }
                Shape::Anchored(pattern) => path
                    .strip_prefix(pattern.as_bytes())
                    .is_some_and(|rest| rest.first().is_none_or(|b| *b == b'/')),
            },
        }
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

impl std::str::FromStr for ExcludePattern {
    type Err = ArchiveError;

    fn from_str(text: &str) -> Result<Self> {
        Self::try_from(text)
    }
}

impl fmt::Display for ExcludePattern {
    /// Writes the normalized pattern text; parsing it again gives an equal
    /// pattern. An anchored name keeps a trailing `/` (`target/`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.shape {
            Shape::MatchAll => f.write_str(GLOBSTAR),
            Shape::Floating(pattern) => f.write_str(pattern),
            Shape::Anchored(pattern) if pattern.contains('/') => f.write_str(pattern),
            Shape::Anchored(pattern) => write!(f, "{pattern}/"),
        }
    }
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

fn is_blank(c: char) -> bool {
    c.is_ascii_whitespace() || c.is_ascii_control()
}

fn parse_shape(text: &str) -> std::result::Result<Shape, ExcludeRefusal> {
    if text.len() > MAX_CONFIG_ENTRY_LENGTH {
        return Err(ExcludeRefusal::TooLong);
    }
    if text.contains('\0') {
        return Err(ExcludeRefusal::ContainsNul);
    }
    if text.is_empty() {
        return Err(ExcludeRefusal::Empty);
    }
    if text.contains(',') {
        return Err(ExcludeRefusal::ContainsComma);
    }
    if text.contains(['{', '}']) {
        return Err(ExcludeRefusal::BraceAlternation);
    }

    let text = text.replace('\\', "/");
    // Anchoring is decided on the raw text, before empty and `.` segments go.
    let anchored = text.contains('/');
    if text.starts_with('/') || (anchored && Path::new(&text).has_root()) {
        return Err(ExcludeRefusal::Absolute);
    }

    let segments: Vec<&str> = text
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    if segments.is_empty() {
        return Err(if text == "." {
            ExcludeRefusal::DotEntry
        } else {
            ExcludeRefusal::Empty
        });
    }
    if segments.contains(&"..") {
        return Err(ExcludeRefusal::DotEntry);
    }
    if anchored
        && !Path::new(&segments.join("/"))
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ExcludeRefusal::Absolute);
    }
    segments
        .iter()
        .try_for_each(|segment| scan_segment(segment))?;

    let mut kept: Vec<&str> = Vec::with_capacity(segments.len());
    for segment in segments {
        if segment == GLOBSTAR && kept.last() == Some(&GLOBSTAR) {
            continue;
        }
        kept.push(segment);
    }
    while kept.last() == Some(&GLOBSTAR) {
        kept.pop();
    }
    // Checked on the canonical segments, so what Display prints parses again.
    let (Some(first), Some(last)) = (kept.first(), kept.last()) else {
        return Ok(Shape::MatchAll);
    };
    if first.starts_with(is_blank) || last.ends_with(is_blank) {
        return Err(ExcludeRefusal::PaddedWithBlank);
    }
    if first.starts_with('!') {
        return Err(ExcludeRefusal::LeadingNegation);
    }
    Ok(match kept.as_slice() {
        [name] if !anchored => Shape::Floating((*name).into()),
        _ => Shape::Anchored(kept.join("/").into()),
    })
}

/// Rejects the constructs where `globset` and this grammar could disagree.
///
/// Stricter than `globset` on purpose: a disagreement between the two parsers
/// can only refuse a pattern, never widen what it matches.
fn scan_segment(segment: &str) -> std::result::Result<(), ExcludeRefusal> {
    if segment == GLOBSTAR {
        return Ok(());
    }
    if segment.contains(GLOBSTAR) {
        return Err(ExcludeRefusal::UnsupportedWildcard);
    }
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        i = match bytes.get(i) {
            Some(b'[') => scan_class(bytes, i + 1)?,
            _ => i + 1,
        };
    }
    Ok(())
}

/// Validates the class whose first member is at `start`; returns the index
/// just past its closing `]`.
fn scan_class(bytes: &[u8], start: usize) -> std::result::Result<usize, ExcludeRefusal> {
    if matches!(bytes.get(start), Some(b'!' | b'^')) {
        return Err(ExcludeRefusal::UnsupportedClass);
    }
    let mut i = start;
    loop {
        let &member = bytes.get(i).ok_or(ExcludeRefusal::UnterminatedClass)?;
        let first = i == start;
        if member == b']' && !first {
            return Ok(i + 1);
        }
        if !member.is_ascii() || (member == b'[' && bytes.get(i + 1) == Some(&b':')) {
            return Err(ExcludeRefusal::UnsupportedClass);
        }
        let range_end = match (bytes.get(i + 1), bytes.get(i + 2)) {
            (Some(b'-'), Some(end)) if *end != b']' => Some(*end),
            _ => None,
        };
        if let Some(end) = range_end {
            if !end.is_ascii() {
                return Err(ExcludeRefusal::UnsupportedClass);
            }
            if !is_alnum_range(member, end) {
                return Err(ExcludeRefusal::InvalidClassRange);
            }
            i += 3;
            continue;
        }
        if member == b'-' && !first && bytes.get(i + 1) != Some(&b']') {
            return Err(ExcludeRefusal::InvalidClassRange);
        }
        i += 1;
    }
}

/// Both ends in one of `0-9`, `a-z`, `A-Z`, and ordered. The lowest allowed
/// end is `0` (0x30), so no allowed range can contain `/` (0x2F).
fn is_alnum_range(low: u8, high: u8) -> bool {
    low <= high
        && ((low.is_ascii_digit() && high.is_ascii_digit())
            || (low.is_ascii_lowercase() && high.is_ascii_lowercase())
            || (low.is_ascii_uppercase() && high.is_ascii_uppercase()))
}

fn is_direct(shape: &Shape) -> bool {
    let plain = |text: &str| !text.contains(['*', '?', '[']);
    match shape {
        Shape::MatchAll => true,
        Shape::Floating(pattern) => plain(pattern.strip_prefix('*').unwrap_or(pattern)),
        Shape::Anchored(pattern) => plain(pattern),
    }
}

fn engine_for(shape: &Shape, allow_direct: bool) -> std::result::Result<Engine, ExcludeRefusal> {
    let texts = match shape {
        Shape::MatchAll => return Ok(Engine::Direct),
        Shape::Floating(pattern) => [format!("**/{pattern}"), format!("**/{pattern}/**")],
        Shape::Anchored(pattern) => [pattern.to_string(), format!("{pattern}/**")],
    };
    if allow_direct && is_direct(shape) {
        return Ok(Engine::Direct);
    }
    let mut builder = GlobSetBuilder::new();
    for text in &texts {
        let glob = GlobBuilder::new(text)
            .literal_separator(true)
            .backslash_escape(false)
            .case_insensitive(false)
            .allow_unclosed_class(false)
            .empty_alternates(false)
            .build()
            .map_err(|error| glob_refusal(error.kind()))?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Engine::Glob)
        .map_err(|error| glob_refusal(error.kind()))
}

fn glob_refusal(kind: &ErrorKind) -> ExcludeRefusal {
    match kind {
        ErrorKind::InvalidRange(..) => ExcludeRefusal::InvalidClassRange,
        _ => ExcludeRefusal::UnsupportedSyntax,
    }
}

/// The `/`-joined normal components of `path`, or `None` when the path can
/// never match: a root, a prefix, a `..` component, or no component at all.
fn normalized(path: &Path) -> Option<Cow<'_, [u8]>> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let canonical = !bytes.is_empty()
        && bytes
            .split(|b| *b == b'/')
            .all(|segment| !segment.is_empty() && segment != b"." && segment != b"..");
    if canonical && !cfg!(windows) {
        return Some(Cow::Borrowed(bytes));
    }
    let mut joined = Vec::with_capacity(bytes.len());
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                if !joined.is_empty() {
                    joined.push(b'/');
                }
                joined.extend_from_slice(name.as_encoded_bytes());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!joined.is_empty()).then_some(Cow::Owned(joined))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn pattern(text: &str) -> ExcludePattern {
        ExcludePattern::try_from(text).unwrap()
    }

    fn glob_only(text: &str) -> ExcludePattern {
        ExcludePattern::from_shape(parse_shape(text).unwrap(), false).unwrap()
    }

    fn refusal(text: &str) -> ExcludeRefusal {
        match ExcludePattern::try_from(text) {
            Err(ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::ExcludePattern,
                problem: ConfigProblem::ExcludePatternRefused { reason, .. },
            }) => reason,
            other => panic!("{text:?} must be refused with a typed reason, got {other:?}"),
        }
    }

    fn selects(text: &str, path: &str) -> bool {
        pattern(text).matches(Path::new(path))
    }

    /// The matcher this module had before globs: four shapes, every
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
    fn issue_examples_select_as_documented() {
        assert!(selects("src/c/*.rs", "src/c/a.rs"));
        assert!(!selects("src/c/*.rs", "src/c/d/a.rs"));
        assert!(!selects("src/c/*.rs", "src/c/a.txt"));
        assert!(selects("src/**/*.rs", "src/a/b/c.rs"));
        assert!(selects("src/**/*.rs", "src/c.rs"));
        assert!(selects("src/*/two.rs", "src/x/two.rs"));
        assert!(!selects("src/*/two.rs", "src/x/y/two.rs"));
        assert!(selects("src/c/t?o.rs", "src/c/two.rs"));
        assert!(!selects("src/c/t?o.rs", "src/c/tho.rs.bak"));
        assert!(selects("[a-c]*", "apple"));
        assert!(selects("[a-c]*", "x/banana"));
        assert!(!selects("[a-c]*", "dog"));
    }

    #[test]
    fn question_mark_matches_exactly_one_byte() {
        assert!(selects("caf?.txt", "cafe.txt"));
        assert!(!selects("caf?.txt", "caf\u{e9}.txt"));
        assert!(!selects("a?b", "a/b"));
        assert!(!selects("a?b", "ab"));
    }

    #[test]
    fn star_never_crosses_a_separator() {
        assert!(!selects("a*b", "a/b"));
        assert!(!selects("src/*.rs", "src/x/y.rs"));
        assert!(selects("a*b", "x/a_b"));
        assert!(selects("*", "anything/at/all"));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(!selects("src", "SRC/a"));
        assert!(!selects("*.TMP", "a.tmp"));
    }

    #[test]
    fn leading_dot_is_not_special() {
        assert!(selects("*", ".hidden"));
        assert!(selects("*.git", ".git"));
        assert!(selects("?git", ".git"));
    }

    #[test]
    fn backslash_is_a_separator_not_an_escape() {
        assert!(selects("src\\c\\*.rs", "src/c/two.rs"));
        assert_eq!(pattern("./a\\b"), pattern("a/b"));
    }

    #[test]
    fn anchoring_is_decided_on_the_raw_text() {
        for text in ["target/", "./build", "build\\", "build/**"] {
            let p = pattern(text);
            let name = text
                .trim_start_matches("./")
                .trim_end_matches(['/', '\\', '*']);
            assert!(p.matches(Path::new(name)), "{text}");
            assert!(p.matches(Path::new(&format!("{name}/x"))), "{text}");
            assert!(!p.matches(Path::new(&format!("a/{name}"))), "{text}");
        }
        assert_ne!(pattern("x"), pattern("./x"));
        assert!(selects("x", "a/x"));
        assert!(!selects("./x", "a/x"));
        assert_eq!(pattern("target/"), pattern("./target"));
        assert_eq!(pattern("target/"), pattern("target/**"));
    }

    #[test]
    fn only_globstar_matches_everything() {
        for text in ["**", "./**", "**/", "**/**", "./**/**/"] {
            let p = pattern(text);
            assert_eq!(p.to_string(), "**", "{text}");
            assert!(p.matches(Path::new("a/b")));
        }
        assert!(!pattern("**").matches(Path::new("")));
    }

    #[test]
    fn display_round_trips() {
        for text in [
            ".git",
            "*.tmp",
            "temp*",
            "build/out",
            "target/",
            "**",
            "src/**/*.rs",
            "a/**/b",
            "[a-c]*",
            "a /b",
            "x/!y",
        ] {
            let p = pattern(text);
            assert_eq!(p.to_string(), text);
            assert_eq!(pattern(&p.to_string()), p);
        }
        for text in ["./!x", "./x", "a//b/", "./a/**", "build\\"] {
            if let Ok(p) = ExcludePattern::try_from(text) {
                assert_eq!(pattern(&p.to_string()), p, "{text}");
            }
        }
        assert_eq!(refusal("./!x"), ExcludeRefusal::LeadingNegation);
        assert_eq!(refusal("a/b /"), ExcludeRefusal::PaddedWithBlank);
        assert_eq!(refusal("./ x"), ExcludeRefusal::PaddedWithBlank);
        assert_eq!(refusal("* /**/"), ExcludeRefusal::PaddedWithBlank);
    }

    #[test]
    fn every_refused_shape_names_a_typed_reason() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let cases: [(&str, ExcludeRefusal); 40] = [
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
            ("a**b", ExcludeRefusal::UnsupportedWildcard),
            ("***", ExcludeRefusal::UnsupportedWildcard),
            ("**a", ExcludeRefusal::UnsupportedWildcard),
            ("a/**b/c", ExcludeRefusal::UnsupportedWildcard),
            ("!a.txt", ExcludeRefusal::LeadingNegation),
            ("{a}", ExcludeRefusal::BraceAlternation),
            ("a}", ExcludeRefusal::BraceAlternation),
            ("a[!x]b", ExcludeRefusal::UnsupportedClass),
            ("a[^x]b", ExcludeRefusal::UnsupportedClass),
            ("[\u{e9}]", ExcludeRefusal::UnsupportedClass),
            ("[[:alpha:]]", ExcludeRefusal::UnsupportedClass),
            ("[a", ExcludeRefusal::UnterminatedClass),
            ("[", ExcludeRefusal::UnterminatedClass),
            ("[]", ExcludeRefusal::UnterminatedClass),
            ("[a/b]", ExcludeRefusal::UnterminatedClass),
            ("[a\\b]", ExcludeRefusal::UnterminatedClass),
            ("x[.-9]y", ExcludeRefusal::InvalidClassRange),
            ("x[+-0]y", ExcludeRefusal::InvalidClassRange),
            ("[--0]", ExcludeRefusal::InvalidClassRange),
            ("[*-0]", ExcludeRefusal::InvalidClassRange),
            ("[]-a]", ExcludeRefusal::InvalidClassRange),
            ("[c-a]", ExcludeRefusal::InvalidClassRange),
            ("[a-c-e]", ExcludeRefusal::InvalidClassRange),
            ("[0-z]", ExcludeRefusal::InvalidClassRange),
            (" .env", ExcludeRefusal::PaddedWithBlank),
            (".env ", ExcludeRefusal::PaddedWithBlank),
            ("a\t", ExcludeRefusal::PaddedWithBlank),
            ("a,b", ExcludeRefusal::ContainsComma),
            ("{a,b}", ExcludeRefusal::ContainsComma),
        ];
        for (text, expected) in cases {
            assert_eq!(refusal(text), expected, "{text:?}");
        }
    }

    #[test]
    fn accepted_class_forms() {
        for text in [
            "[a-c]", "[0-9]", "[-a]", "[a-]", "[]a]", "[a-cx-z]", "[*]", "[?]", "[[]", "a]",
        ] {
            assert!(ExcludePattern::try_from(text).is_ok(), "{text}");
        }
        assert!(selects("[*]x", "*x"));
        assert!(!selects("[*]x", "ax"));
        assert!(selects("[]a]", "]"));
        assert!(selects("[a-]", "-"));
    }

    #[test]
    fn a_class_never_matches_a_separator() {
        assert!(!selects("x[0-9]y", "x/y"));
        assert!(!selects("a[b-c]d", "a/d"));
    }

    #[test]
    fn a_refusal_message_quotes_the_pattern() {
        let err = ExcludePattern::try_from("{a}").unwrap_err();
        let ArchiveError::InvalidConfiguration { setting, problem } = err else {
            panic!("expected an invalid configuration");
        };
        let message = setting.describe(&problem);
        assert!(message.starts_with("exclude pattern \"{a}\" "), "{message}");
    }

    #[test]
    fn matching_normalizes_the_path() {
        assert!(selects("build/out", "build//out/x"));
        assert!(selects("build/out", "build/./out"));
        assert!(selects("build/out", "./build/out"));
        assert!(selects("build/out", "build/out/"));
        assert!(!selects("a/*/b", "a//b"));
        for text in ["x", "x/y", "**", "*", "y", "/x"]
            .iter()
            .filter_map(|t| ExcludePattern::try_from(*t).ok())
        {
            for path in ["x/../y", "/x", "..", "", "."] {
                assert!(!text.matches(Path::new(path)), "{text} {path}");
            }
        }
    }

    #[test]
    fn literal_and_glob_paths_agree_on_odd_paths() {
        let paths = [
            "x/../y",
            "/build",
            "build",
            "build/x",
            "x/build",
            "./build",
            "build//x",
            "a/./build",
            "b.tmp",
            "x/b.tmp/y",
            "",
            ".",
            "..",
            "build/",
            "a//",
            ".git/config",
        ];
        for text in [
            ".git", "build", "*.tmp", "build/x", "a/build", "target/", "**", "x",
        ] {
            let direct = pattern(text);
            let glob = glob_only(text);
            for path in paths {
                assert_eq!(
                    direct.matches(Path::new(path)),
                    glob.matches(Path::new(path)),
                    "{text:?} vs {path:?}"
                );
            }
        }
    }

    #[test]
    fn defaults_select_a_sample_path() {
        let defaults = [
            (ExcludePattern::literal_name(".git"), ".git/config"),
            (ExcludePattern::literal_name(".DS_Store"), "a/.DS_Store"),
            (ExcludePattern::suffix_name(".tmp"), "x/y.tmp"),
        ];
        for (p, sample) in defaults {
            assert!(p.matches(Path::new(sample)), "{p}");
        }
        assert_eq!(ExcludePattern::suffix_name(".tmp"), pattern("*.tmp"));
        assert_eq!(ExcludePattern::literal_name(".git"), pattern(".git"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_components_match_by_their_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let key = Path::new(OsStr::from_bytes(b"dir/\xff.key"));
        assert!(pattern("*.key").matches(key));
        assert!(pattern("dir").matches(key));
        assert!(pattern("dir/*.key").matches(key));
        assert!(pattern("dir/?.key").matches(key));
        assert!(!pattern("*.pem").matches(key));
        assert!(pattern("dir/").matches(key));
    }

    #[test]
    fn globset_traps_are_closed() {
        assert!(!selects("a[0-9]b", "a/b"));
        assert_eq!(refusal("a{b,c}d"), ExcludeRefusal::ContainsComma);
        assert_eq!(refusal("a{b}d"), ExcludeRefusal::BraceAlternation);
    }

    #[test]
    fn ancestors_of_the_root_no_longer_match() {
        assert!(legacy_matches(Path::new("job.tmp/a.txt"), "*.tmp"));
        assert!(!pattern("*.tmp").matches(Path::new("a.txt")));
    }

    fn name_strategy() -> impl Strategy<Value = String> {
        "[a-c_][a-c._]{0,2}"
    }

    fn path_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(name_strategy(), 1..4).prop_map(|parts| parts.join("/"))
    }

    proptest! {
        #[test]
        fn legacy_shapes_select_the_same_entries(
            name in name_strategy(),
            shape in 0_u8..4,
            tail in name_strategy(),
            path in path_strategy(),
        ) {
            let text = match shape {
                0 => name,
                1 => format!("{name}*"),
                2 => format!("*{name}"),
                _ => format!("{name}/{tail}"),
            };
            prop_assume!(text != "." && text != ".." && !text.split('/').any(|s| s == "." || s == ".."));
            let new = pattern(&text);
            let old = if shape == 3 {
                Path::new(&path).starts_with(&text)
            } else {
                legacy_matches(Path::new(&path), &text)
            };
            prop_assert_eq!(new.matches(Path::new(&path)), old, "{} vs {}", text, path);
        }

        #[test]
        fn direct_and_glob_engines_agree(name in name_strategy(), tail in name_strategy(), path in path_strategy(), anchored in any::<bool>()) {
            let text = if anchored { format!("{name}/{tail}") } else { name };
            let direct = pattern(&text);
            let glob = glob_only(&text);
            prop_assert_eq!(direct.matches(Path::new(&path)), glob.matches(Path::new(&path)));
        }

        #[test]
        fn a_slashless_pattern_matches_only_through_one_component(
            text in "[a-c.?*\\[\\]0-9-]{1,6}",
            path in path_strategy(),
        ) {
            prop_assume!(
                !path.contains('\\')
                    && path.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
            );
            if let Ok(p) = ExcludePattern::try_from(text.as_str())
                && p.matches(Path::new(&path))
            {
                let some_component = Path::new(&path)
                    .components()
                    .any(|c| p.matches(Path::new(c.as_os_str())));
                prop_assert!(some_component, "{} vs {}", text, path);
            }
        }

        #[test]
        fn parse_display_round_trips_and_never_panics(text in "\\PC{0,24}") {
            if let Ok(p) = ExcludePattern::try_from(text.as_str()) {
                let again = ExcludePattern::try_from(p.to_string().as_str());
                prop_assert_eq!(again.ok(), Some(p));
            }
        }
    }
}
