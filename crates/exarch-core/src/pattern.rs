//! Glob patterns that select archive entries.
//!
//! One grammar serves `create --exclude` and the extraction include/exclude
//! lists. [`EntryPattern`] hides its matching engine: no `globset` type
//! appears in a public signature, so the dependency can change without a
//! semver break.

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::PatternRefusal;
use crate::Result;
use crate::security::boundary::MAX_CONFIG_ENTRY_LENGTH;
use globset::Candidate;
use globset::ErrorKind;
use globset::Glob;
use globset::GlobBuilder;
use globset::GlobSet;
use globset::GlobSetBuilder;
use std::borrow::Cow;
use std::fmt;
use std::ops::ControlFlow;
use std::path::Component;
use std::path::Path;
use std::sync::OnceLock;

mod direct_index;

use direct_index::DirectIndex;

const GLOBSTAR: &str = "**";

/// What a parsed pattern selects, before it is given a matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// What a glob pattern selects; never every path.
#[derive(Debug, Clone)]
enum GlobShape {
    /// See [`Shape::Floating`].
    Floating(Box<str>),
    /// See [`Shape::Anchored`].
    Anchored(Box<str>),
}

/// How a pattern is matched. The shape and the engine are one value, so a
/// plain comparison can never be paired with a pattern that needs a glob.
#[derive(Clone)]
enum Matcher {
    /// Every path.
    All,
    /// A literal component name, tested against every path component.
    Name(Box<str>),
    /// The part after the `*` of a `*suffix` name, tested against the end of
    /// every path component.
    Suffix(Box<str>),
    /// A literal anchored path, tested against the start of the path.
    Path(Box<str>),
    /// A pattern with `*`, `?` or `[`, matched by the compiled `set`.
    Glob { shape: GlobShape, set: GlobSet },
}

/// What two patterns are compared by: two patterns are equal when they reduce
/// to the same canonical form (`target/` equals `./target`, but `x` does not
/// equal `./x`). Equal patterns select the same paths; the converse does not
/// hold (`x` and `**/x` select the same paths and stay unequal).
#[derive(Debug, PartialEq, Eq, Hash)]
enum Key<'a> {
    All,
    Name(&'a str),
    Suffix(&'a str),
    FloatingGlob(&'a str),
    Path(&'a str),
    AnchoredGlob(&'a str),
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
/// `0-9`, `a-z` and `A-Z`. See [`PatternRefusal`].
///
/// # Resources
///
/// Pattern length is bounded; the number of patterns is not. Each pattern
/// that uses `*`, `?`, `[` or `**` owns a compiled matcher whose lazily
/// grown search cache can reach 10 MiB per thread under adversarial input.
/// A list of patterns used for selection or exclusion compiles one combined
/// matcher instead, so matching an entry is one scan and the cache does not
/// grow with the number of patterns.
///
/// # Examples
///
/// ```
/// use exarch_core::EntryPattern;
/// use std::path::Path;
///
/// let tmp = EntryPattern::try_from("*.tmp")?;
/// assert!(tmp.matches(Path::new("cache/a.tmp")));
/// assert!(!tmp.matches(Path::new("cache/a.txt")));
///
/// let rs = EntryPattern::try_from("src/**/*.rs")?;
/// assert!(rs.matches(Path::new("src/a/b/lib.rs")));
/// assert!(rs.matches(Path::new("src/lib.rs")));
/// assert!(!rs.matches(Path::new("tests/lib.rs")));
///
/// let out = EntryPattern::try_from("build/out")?;
/// assert!(out.matches(Path::new("build/out/bin/app")));
/// assert!(!out.matches(Path::new("src/build/out")));
///
/// assert!(EntryPattern::try_from("a{b,c}").is_err());
/// assert!(EntryPattern::try_from("!keep").is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Clone)]
pub struct EntryPattern {
    matcher: Matcher,
}

const _: () = {
    const fn auto_traits<
        T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >() {
    }
    auto_traits::<EntryPattern>();
};

impl PartialEq for EntryPattern {
    fn eq(&self, other: &Self) -> bool {
        self.matcher.key() == other.matcher.key()
    }
}

impl Eq for EntryPattern {}

impl std::hash::Hash for EntryPattern {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.matcher.key().hash(state);
    }
}

impl fmt::Debug for EntryPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryPattern({self})")
    }
}

impl EntryPattern {
    /// A pattern naming one literal component, for the built-in defaults.
    pub(crate) fn literal_name(name: &'static str) -> Self {
        Self {
            matcher: Matcher::Name(name.into()),
        }
    }

    /// A pattern for the components ending in `suffix` (`*suffix`), for the
    /// built-in defaults.
    pub(crate) fn suffix_name(suffix: &'static str) -> Self {
        Self {
            matcher: Matcher::Suffix(suffix.into()),
        }
    }

    fn from_shape(shape: Shape) -> std::result::Result<Self, PatternRefusal> {
        Ok(Self {
            matcher: Matcher::from_shape(shape)?,
        })
    }

    /// Parses `text`, naming `setting` in the refusal.
    ///
    /// One grammar serves every use of a pattern: pass
    /// [`ConfigSetting::ExcludePattern`] for creation,
    /// [`ConfigSetting::EntryInclude`] or [`ConfigSetting::EntryExclude`] for
    /// extraction. [`TryFrom<&str>`] is the creation form. The syntax and its
    /// meaning are described on [`EntryPattern`].
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming `setting`, with
    /// [`ConfigProblem::PatternRefused`], which names the pattern and an
    /// [`PatternRefusal`] for the refused shape.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ConfigSetting;
    /// use exarch_core::EntryPattern;
    ///
    /// let pattern = EntryPattern::parse_for(ConfigSetting::EntryInclude, "docs/api")?;
    /// assert_eq!(pattern.to_string(), "docs/api");
    /// assert!(EntryPattern::parse_for(ConfigSetting::EntryInclude, "a**b").is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn parse_for(setting: ConfigSetting, text: &str) -> Result<Self> {
        parse_shape(text)
            .and_then(Self::from_shape)
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
    /// use exarch_core::EntryPattern;
    /// use std::path::Path;
    ///
    /// let p = EntryPattern::try_from("build/out")?;
    /// assert!(p.matches(Path::new("build//out/./x")));
    /// assert!(!p.matches(Path::new("build/../out")));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    pub fn matches(&self, archive_path: &Path) -> bool {
        normalized(archive_path).is_some_and(|path| self.matches_normalized(&path))
    }

    /// Matches a path already reduced by [`normalized`], so a caller testing
    /// many patterns against one entry normalizes it once.
    pub(crate) fn matches_normalized(&self, path: &[u8]) -> bool {
        match &self.matcher {
            Matcher::All => true,
            Matcher::Name(name) => path
                .split(|b| *b == b'/')
                .any(|component| component == name.as_bytes()),
            Matcher::Suffix(suffix) => path
                .split(|b| *b == b'/')
                .any(|component| component.ends_with(suffix.as_bytes())),
            Matcher::Path(anchored) => path
                .strip_prefix(anchored.as_bytes())
                .is_some_and(|rest| rest.first().is_none_or(|b| *b == b'/')),
            Matcher::Glob { set, .. } => set.is_match_candidate(&Candidate::from_bytes(path)),
        }
    }
}

impl TryFrom<&str> for EntryPattern {
    type Error = ArchiveError;

    /// Parses a creation exclude pattern; see [`EntryPattern::parse_for`].
    ///
    /// # Errors
    ///
    /// Refusals name [`ConfigSetting::ExcludePattern`].
    fn try_from(text: &str) -> Result<Self> {
        Self::parse_for(ConfigSetting::ExcludePattern, text)
    }
}

impl std::str::FromStr for EntryPattern {
    type Err = ArchiveError;

    fn from_str(text: &str) -> Result<Self> {
        Self::try_from(text)
    }
}

impl fmt::Display for EntryPattern {
    /// Writes the normalized pattern text; parsing it again gives an equal
    /// pattern. An anchored name keeps a trailing `/` (`target/`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.matcher.key() {
            Key::All => f.write_str(GLOBSTAR),
            Key::Name(pattern) | Key::FloatingGlob(pattern) => f.write_str(pattern),
            Key::Suffix(suffix) => write!(f, "*{suffix}"),
            Key::Path(pattern) | Key::AnchoredGlob(pattern) if pattern.contains('/') => {
                f.write_str(pattern)
            }
            Key::Path(pattern) | Key::AnchoredGlob(pattern) => write!(f, "{pattern}/"),
        }
    }
}

fn refuse(setting: ConfigSetting, text: &str, reason: PatternRefusal) -> ArchiveError {
    let end = text.floor_char_boundary(MAX_CONFIG_ENTRY_LENGTH);
    ArchiveError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::PatternRefused {
            pattern: text.get(..end).unwrap_or(text).to_owned(),
            reason,
        },
    }
}

/// `C:`-style prefix; refused on every host so a pattern means the same
/// thing wherever it is parsed.
fn has_drive_prefix(segment: &str) -> bool {
    matches!(segment.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic())
}

fn is_blank(c: char) -> bool {
    c.is_ascii_whitespace() || c.is_ascii_control()
}

fn parse_shape(text: &str) -> std::result::Result<Shape, PatternRefusal> {
    if text.len() > MAX_CONFIG_ENTRY_LENGTH {
        return Err(PatternRefusal::TooLong);
    }
    if text.contains('\0') {
        return Err(PatternRefusal::ContainsNul);
    }
    if text.is_empty() {
        return Err(PatternRefusal::Empty);
    }
    if text.contains(',') {
        return Err(PatternRefusal::ContainsComma);
    }
    if text.contains(['{', '}']) {
        return Err(PatternRefusal::BraceAlternation);
    }

    let text = text.replace('\\', "/");
    // Anchoring is decided on the raw text, before empty and `.` segments go.
    let anchored = text.contains('/');
    if text.starts_with('/') || (anchored && Path::new(&text).has_root()) {
        return Err(PatternRefusal::Absolute);
    }

    let segments: Vec<&str> = text
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    if segments.is_empty() {
        return Err(if text == "." {
            PatternRefusal::DotEntry
        } else {
            PatternRefusal::Empty
        });
    }
    if segments.contains(&"..") {
        return Err(PatternRefusal::DotEntry);
    }
    if segments
        .first()
        .is_some_and(|first| has_drive_prefix(first))
        || !Path::new(&segments.join("/"))
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(PatternRefusal::Absolute);
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
    let (Some(first), Some(last)) = (
        kept.iter().find(|segment| **segment != GLOBSTAR),
        kept.last(),
    ) else {
        return Ok(Shape::MatchAll);
    };
    if first.starts_with(is_blank) || last.ends_with(is_blank) {
        return Err(PatternRefusal::PaddedWithBlank);
    }
    if first.starts_with('!') {
        return Err(PatternRefusal::LeadingNegation);
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
fn scan_segment(segment: &str) -> std::result::Result<(), PatternRefusal> {
    if segment == GLOBSTAR {
        return Ok(());
    }
    if segment.contains(GLOBSTAR) {
        return Err(PatternRefusal::UnsupportedWildcard);
    }
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        i = match bytes.get(i) {
            Some(b'[') => scan_class(bytes, i.saturating_add(1))?,
            _ => i.saturating_add(1),
        };
    }
    Ok(())
}

/// Validates the class whose first member is at `start`; returns the index
/// just past its closing `]`.
fn scan_class(bytes: &[u8], start: usize) -> std::result::Result<usize, PatternRefusal> {
    if matches!(bytes.get(start), Some(b'!' | b'^')) {
        return Err(PatternRefusal::UnsupportedClass);
    }
    let mut i = start;
    loop {
        let &member = bytes.get(i).ok_or(PatternRefusal::UnterminatedClass)?;
        let first = i == start;
        let at = |offset: usize| bytes.get(i.saturating_add(offset));
        if member == b']' && !first {
            return Ok(i.saturating_add(1));
        }
        if !member.is_ascii() || (member == b'[' && at(1) == Some(&b':')) {
            return Err(PatternRefusal::UnsupportedClass);
        }
        let range_end = match (at(1), at(2)) {
            (Some(b'-'), Some(end)) if *end != b']' => Some(*end),
            _ => None,
        };
        if let Some(end) = range_end {
            if !end.is_ascii() {
                return Err(PatternRefusal::UnsupportedClass);
            }
            if !is_alnum_range(member, end) {
                return Err(PatternRefusal::InvalidClassRange);
            }
            i = i.saturating_add(3);
            continue;
        }
        if member == b'-' && !first && at(1) != Some(&b']') {
            return Err(PatternRefusal::InvalidClassRange);
        }
        i = i.saturating_add(1);
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

fn is_plain(text: &str) -> bool {
    !text.contains(['*', '?', '['])
}

impl Matcher {
    fn from_shape(shape: Shape) -> std::result::Result<Self, PatternRefusal> {
        match shape {
            Shape::MatchAll => Ok(Self::All),
            Shape::Floating(name) => match name.strip_prefix('*') {
                Some(suffix) if is_plain(suffix) => Ok(Self::Suffix(suffix.into())),
                None if is_plain(&name) => Ok(Self::Name(name)),
                Some(_) | None => Self::glob(GlobShape::Floating(name)),
            },
            Shape::Anchored(path) if is_plain(&path) => Ok(Self::Path(path)),
            Shape::Anchored(path) => Self::glob(GlobShape::Anchored(path)),
        }
    }

    /// The glob matcher for `shape`: the shape's own glob plus its subtree
    /// twin.
    fn glob(shape: GlobShape) -> std::result::Result<Self, PatternRefusal> {
        let mut builder = GlobSetBuilder::new();
        for text in &glob_texts(&shape) {
            builder.add(build_glob(text)?);
        }
        let set = builder
            .build()
            .map_err(|error| glob_refusal(error.kind()))?;
        Ok(Self::Glob { shape, set })
    }

    fn key(&self) -> Key<'_> {
        match self {
            Self::All => Key::All,
            Self::Name(name) => Key::Name(name),
            Self::Suffix(suffix) => Key::Suffix(suffix),
            Self::Path(path) => Key::Path(path),
            Self::Glob {
                shape: GlobShape::Floating(pattern),
                ..
            } => Key::FloatingGlob(pattern),
            Self::Glob {
                shape: GlobShape::Anchored(pattern),
                ..
            } => Key::AnchoredGlob(pattern),
        }
    }
}

/// The glob texts for `shape`: its own glob plus its subtree twin.
fn glob_texts(shape: &GlobShape) -> [String; 2] {
    match shape {
        GlobShape::Floating(pattern) => [format!("**/{pattern}"), format!("**/{pattern}/**")],
        GlobShape::Anchored(pattern) => [pattern.to_string(), format!("{pattern}/**")],
    }
}

/// The one place a glob text is compiled, so a single pattern and a combined
/// list can never disagree on the flags.
fn build_glob(text: &str) -> std::result::Result<Glob, PatternRefusal> {
    GlobBuilder::new(text)
        .literal_separator(true)
        .backslash_escape(false)
        .case_insensitive(false)
        .allow_unclosed_class(false)
        .empty_alternates(false)
        .build()
        .map_err(|error| glob_refusal(error.kind()))
}

fn glob_refusal(kind: &ErrorKind) -> PatternRefusal {
    match kind {
        ErrorKind::InvalidRange(..) => PatternRefusal::InvalidClassRange,
        _ => PatternRefusal::UnsupportedSyntax,
    }
}

impl EntryPattern {
    fn glob_texts(&self) -> Option<[String; 2]> {
        match &self.matcher {
            Matcher::Glob { shape, .. } => Some(glob_texts(shape)),
            Matcher::All | Matcher::Name(_) | Matcher::Suffix(_) | Matcher::Path(_) => None,
        }
    }
}

/// How a [`PatternList`] matches its glob patterns.
enum GlobIndex {
    /// One automaton over every glob pattern; `owner` maps a glob of the set
    /// back to the index of its pattern.
    Combined { globs: GlobSet, owner: Box<[usize]> },
    /// The combined automaton could not be compiled, so each glob pattern
    /// matches on its own.
    Separate,
}

/// How a [`PatternList`] matches: direct patterns through one index over the
/// path, glob patterns through [`GlobIndex`].
struct ListIndex {
    direct: DirectIndex,
    globs: GlobIndex,
}

/// An ordered list of patterns matched against an entry in one pass.
///
/// Compiled on first use, so building a list pattern by pattern stays linear.
#[derive(Default)]
pub(crate) struct PatternList {
    patterns: Box<[EntryPattern]>,
    index: OnceLock<ListIndex>,
}

impl Clone for PatternList {
    fn clone(&self) -> Self {
        Self::from(self.patterns.to_vec())
    }
}

impl PartialEq for PatternList {
    fn eq(&self, other: &Self) -> bool {
        self.patterns == other.patterns
    }
}

impl Eq for PatternList {}

impl fmt::Debug for PatternList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.patterns.iter()).finish()
    }
}

impl From<Vec<EntryPattern>> for PatternList {
    fn from(patterns: Vec<EntryPattern>) -> Self {
        Self {
            patterns: patterns.into_boxed_slice(),
            index: OnceLock::new(),
        }
    }
}

impl PatternList {
    /// The patterns, in the order they were added.
    pub(crate) fn as_slice(&self) -> &[EntryPattern] {
        &self.patterns
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// This list with `pattern` appended.
    pub(crate) fn pushed(self, pattern: EntryPattern) -> Self {
        let mut patterns = self.patterns.into_vec();
        patterns.push(pattern);
        Self::from(patterns)
    }

    fn index(&self) -> &ListIndex {
        self.index.get_or_init(|| ListIndex {
            direct: DirectIndex::new(self.patterns.iter().enumerate()),
            globs: self.glob_index(),
        })
    }

    fn glob_index(&self) -> GlobIndex {
        let mut builder = GlobSetBuilder::new();
        let mut owner = Vec::new();
        for (position, pattern) in self.patterns.iter().enumerate() {
            for text in pattern.glob_texts().iter().flatten() {
                let Ok(glob) = build_glob(text) else {
                    return GlobIndex::Separate;
                };
                builder.add(glob);
                owner.push(position);
            }
        }
        builder
            .build()
            .map_or(GlobIndex::Separate, |globs| GlobIndex::Combined {
                globs,
                owner: owner.into_boxed_slice(),
            })
    }

    fn glob_patterns(&self) -> impl Iterator<Item = (usize, &EntryPattern)> {
        self.patterns
            .iter()
            .enumerate()
            .filter(|(_, pattern)| matches!(pattern.matcher, Matcher::Glob { .. }))
    }

    /// Calls `visit` with the index of every pattern that matches `path`, a
    /// path already reduced by [`normalized`]; a pattern may be visited twice.
    ///
    /// `scratch` holds the glob matches, so a caller matching many entries
    /// passes the same buffer each time and allocates once.
    pub(crate) fn matching(
        &self,
        path: Option<&[u8]>,
        scratch: &mut Vec<usize>,
        mut visit: impl FnMut(usize),
    ) {
        let Some(path) = path else { return };
        let index = self.index();
        let _ = index.direct.visit(path, |position| {
            visit(position);
            ControlFlow::Continue(())
        });
        match &index.globs {
            GlobIndex::Combined { globs, owner } => {
                globs.matches_candidate_into(&Candidate::from_bytes(path), scratch);
                scratch
                    .iter()
                    .filter_map(|glob| owner.get(*glob).copied())
                    .for_each(visit);
            }
            GlobIndex::Separate => {
                for (position, pattern) in self.glob_patterns() {
                    if pattern.matches_normalized(path) {
                        visit(position);
                    }
                }
            }
        }
    }

    /// Whether any pattern matches `path`, a path already reduced by
    /// [`normalized`]. Never allocates.
    pub(crate) fn any_match(&self, path: Option<&[u8]>) -> bool {
        let Some(path) = path else { return false };
        let index = self.index();
        index
            .direct
            .visit(path, |_| ControlFlow::Break(()))
            .is_break()
            || match &index.globs {
                GlobIndex::Combined { globs, .. } => {
                    globs.is_match_candidate(&Candidate::from_bytes(path))
                }
                GlobIndex::Separate => self
                    .glob_patterns()
                    .any(|(_, pattern)| pattern.matches_normalized(path)),
            }
    }
}

/// The `/`-joined normal components of `path`, or `None` when the path can
/// never match: a root, a prefix, a `..` component, or no component at all.
pub(crate) fn normalized(path: &Path) -> Option<Cow<'_, [u8]>> {
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

    fn pattern(text: &str) -> EntryPattern {
        EntryPattern::try_from(text).unwrap()
    }

    fn glob_only(text: &str) -> EntryPattern {
        let matcher = match parse_shape(text).unwrap() {
            Shape::MatchAll => Matcher::All,
            Shape::Floating(name) => Matcher::glob(GlobShape::Floating(name)).unwrap(),
            Shape::Anchored(path) => Matcher::glob(GlobShape::Anchored(path)).unwrap(),
        };
        EntryPattern { matcher }
    }

    fn refusal(text: &str) -> PatternRefusal {
        match EntryPattern::try_from(text) {
            Err(ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::ExcludePattern,
                problem: ConfigProblem::PatternRefused { reason, .. },
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
        for (text, shown) in [
            ("./x", "x/"),
            ("a//b/", "a/b"),
            ("./a/**", "a/"),
            ("build\\", "build/"),
        ] {
            let p = pattern(text);
            assert_eq!(p.to_string(), shown, "{text}");
            assert_eq!(pattern(shown), p, "{text}");
        }
        assert_eq!(refusal("./!x"), PatternRefusal::LeadingNegation);
        assert_eq!(refusal("**/!x"), PatternRefusal::LeadingNegation);
        assert_eq!(refusal("**/ x"), PatternRefusal::PaddedWithBlank);
        assert_eq!(refusal("a/b /"), PatternRefusal::PaddedWithBlank);
        assert_eq!(refusal("./ x"), PatternRefusal::PaddedWithBlank);
        assert_eq!(refusal("* /**/"), PatternRefusal::PaddedWithBlank);
    }

    #[test]
    fn every_refused_shape_names_a_typed_reason() {
        let long = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let cases: [(&str, PatternRefusal); 40] = [
            ("", PatternRefusal::Empty),
            ("./", PatternRefusal::Empty),
            ("bad\0nul", PatternRefusal::ContainsNul),
            (&long, PatternRefusal::TooLong),
            ("..", PatternRefusal::DotEntry),
            (".", PatternRefusal::DotEntry),
            ("../x", PatternRefusal::DotEntry),
            ("a/../b", PatternRefusal::DotEntry),
            ("/abs", PatternRefusal::Absolute),
            ("\\abs", PatternRefusal::Absolute),
            ("/", PatternRefusal::Absolute),
            ("a**b", PatternRefusal::UnsupportedWildcard),
            ("***", PatternRefusal::UnsupportedWildcard),
            ("**a", PatternRefusal::UnsupportedWildcard),
            ("a/**b/c", PatternRefusal::UnsupportedWildcard),
            ("!a.txt", PatternRefusal::LeadingNegation),
            ("{a}", PatternRefusal::BraceAlternation),
            ("a}", PatternRefusal::BraceAlternation),
            ("a[!x]b", PatternRefusal::UnsupportedClass),
            ("a[^x]b", PatternRefusal::UnsupportedClass),
            ("[\u{e9}]", PatternRefusal::UnsupportedClass),
            ("[[:alpha:]]", PatternRefusal::UnsupportedClass),
            ("[a", PatternRefusal::UnterminatedClass),
            ("[", PatternRefusal::UnterminatedClass),
            ("[]", PatternRefusal::UnterminatedClass),
            ("[a/b]", PatternRefusal::UnterminatedClass),
            ("[a\\b]", PatternRefusal::UnterminatedClass),
            ("x[.-9]y", PatternRefusal::InvalidClassRange),
            ("x[+-0]y", PatternRefusal::InvalidClassRange),
            ("[--0]", PatternRefusal::InvalidClassRange),
            ("[*-0]", PatternRefusal::InvalidClassRange),
            ("[]-a]", PatternRefusal::InvalidClassRange),
            ("[c-a]", PatternRefusal::InvalidClassRange),
            ("[a-c-e]", PatternRefusal::InvalidClassRange),
            ("[0-z]", PatternRefusal::InvalidClassRange),
            (" .env", PatternRefusal::PaddedWithBlank),
            (".env ", PatternRefusal::PaddedWithBlank),
            ("a\t", PatternRefusal::PaddedWithBlank),
            ("a,b", PatternRefusal::ContainsComma),
            ("{a,b}", PatternRefusal::ContainsComma),
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
            assert!(EntryPattern::try_from(text).is_ok(), "{text}");
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
        let err = EntryPattern::try_from("{a}").unwrap_err();
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
        // `a` names a component of `a/../a`, but a `..` path matches nothing,
        // which is why the component oracle is limited to plain paths.
        assert!(!selects("a", "a/../a"));
        assert!(!selects("a/*", "a/../a/b"));
        for text in ["x", "x/y", "**", "*", "y", "/x"]
            .iter()
            .filter_map(|t| EntryPattern::try_from(*t).ok())
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
            (EntryPattern::literal_name(".git"), ".git/config"),
            (EntryPattern::literal_name(".DS_Store"), "a/.DS_Store"),
            (EntryPattern::suffix_name(".tmp"), "x/y.tmp"),
        ];
        for (p, sample) in defaults {
            assert!(p.matches(Path::new(sample)), "{p}");
        }
        assert_eq!(EntryPattern::suffix_name(".tmp"), pattern("*.tmp"));
        assert_eq!(EntryPattern::literal_name(".git"), pattern(".git"));
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
    fn glob_patterns_select_descendants_through_the_subtree_twin() {
        for (text, path) in [
            ("src/*", "src/x/y"),
            ("src/*", "src/x"),
            ("[a-c]*", "x/banana/deep"),
            ("**/foo", "a/foo/b"),
            ("**/foo", "foo/b"),
            ("a?c/x", "abc/x/y"),
            ("src/[a-c]*", "src/b/c/d"),
        ] {
            assert!(glob_only(text).matches(Path::new(path)), "{text} {path}");
            assert!(selects(text, path), "{text} {path}");
        }
        assert!(!selects("src/*", "src"));
        assert!(!selects("**/foo", "a/foobar"));
    }

    #[test]
    fn double_star_forms_are_anchored_and_span_directories() {
        for text in ["**/x", "**/x/**", "./**/x"] {
            let p = pattern(text);
            assert_eq!(p.to_string(), "**/x", "{text}");
            assert!(p.matches(Path::new("x")), "{text}");
            assert!(p.matches(Path::new("a/b/x/y")), "{text}");
            assert!(!p.matches(Path::new("a/xx")), "{text}");
        }
        assert_ne!(pattern("**/x"), pattern("x"));
    }

    #[test]
    fn the_length_limit_is_255_bytes() {
        let at_limit = "x".repeat(MAX_CONFIG_ENTRY_LENGTH);
        assert_eq!(MAX_CONFIG_ENTRY_LENGTH, 255);
        assert!(EntryPattern::try_from(at_limit.as_str()).is_ok());
        assert_eq!(refusal(&format!("{at_limit}x")), PatternRefusal::TooLong);
    }

    #[test]
    fn a_drive_prefix_is_refused_on_every_host() {
        for text in ["C:x", "c:", "C:/x", "C:\\x", "./C:x"] {
            assert_eq!(refusal(text), PatternRefusal::Absolute, "{text}");
        }
        assert!(EntryPattern::try_from("**/C:x").is_ok());
        assert!(EntryPattern::try_from("ab:c").is_ok());
        assert!(EntryPattern::try_from("x/C:y").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn host_separators_and_prefixes() {
        assert!(pattern("src/c/*.rs").matches(Path::new("src\\c\\two.rs")));
        assert!(!pattern("src/c/*.rs").matches(Path::new("C:\\src\\c\\two.rs")));
        assert_eq!(refusal("C:x"), PatternRefusal::Absolute);
    }

    type Positions = std::collections::BTreeSet<usize>;

    fn visited(list: &PatternList, path: &[u8]) -> Positions {
        let mut found = Positions::new();
        list.matching(Some(path), &mut Vec::new(), |index| {
            found.insert(index);
        });
        found
    }

    fn own_results(patterns: &[EntryPattern], path: &[u8]) -> Positions {
        patterns
            .iter()
            .enumerate()
            .filter(|(_, pattern)| pattern.matches_normalized(path))
            .map(|(index, _)| index)
            .collect()
    }

    fn edge_patterns() -> Vec<EntryPattern> {
        let long_name = "a".repeat(255);
        let long_suffix = format!("*{}", "a".repeat(254));
        let long_anchored = format!("x/{}", "a".repeat(252));
        [
            "*",
            "*b",
            "*ab",
            "*\u{e9}",
            "\u{e9}",
            "x",
            "./x",
            "x/d",
            "a/b",
            "target",
            "*.tmp",
            "a/*",
            &long_name,
            &long_suffix,
            &long_anchored,
        ]
        .iter()
        .map(|text| pattern(text))
        .collect()
    }

    fn edge_paths() -> Vec<Vec<u8>> {
        let mut paths: Vec<Vec<u8>> = [
            &b"b"[..],
            b"ab",
            b"xab",
            b"",
            b"/",
            b"a//b",
            b"a/",
            b"/a",
            b"a/b/c",
            b"x",
            b"x/y",
            b"y/x",
            b"a.tmp",
            &[0xFF],
            &[b'a', 0xFF],
            &[0xA9],
            &[0xC3],
            &[b'x', b'/', 0xFF, 0xC3, 0xA9],
        ]
        .iter()
        .map(|path| path.to_vec())
        .collect();
        paths.extend(
            ["\u{e9}", "caf\u{e9}", "x/\u{e9}", "\u{e9}/x"]
                .iter()
                .map(|path| path.as_bytes().to_vec()),
        );
        for length in [253, 254, 255, 256, 300] {
            let run = "a".repeat(length);
            paths.push(run.clone().into_bytes());
            paths.push(format!("x/{run}").into_bytes());
            paths.push(format!("x/{run}/z").into_bytes());
        }
        paths.push("x/d/".repeat(300).into_bytes());
        paths
    }

    #[test]
    fn a_list_agrees_with_its_patterns_on_edge_paths() {
        let patterns = edge_patterns();
        let list = PatternList::from(patterns.clone());
        for path in edge_paths() {
            assert_eq!(
                visited(&list, &path),
                own_results(&patterns, &path),
                "{:?}",
                String::from_utf8_lossy(&path)
            );
            assert_eq!(
                list.any_match(Some(&path)),
                !own_results(&patterns, &path).is_empty()
            );
        }
        assert!(
            visited(&list, &[0xFF]).contains(&0),
            "`*` matches raw bytes"
        );
        assert!(
            !visited(&list, &[0xA9]).contains(&3),
            "a split multi-byte suffix"
        );
        assert!(visited(&list, "caf\u{e9}".as_bytes()).contains(&3));
    }

    #[test]
    fn the_separate_glob_fallback_agrees_with_the_combined_index() {
        let patterns = edge_patterns();
        let list = PatternList::from(patterns.clone());
        let direct = DirectIndex::new(patterns.iter().enumerate());
        assert!(
            list.index
                .set(ListIndex {
                    direct,
                    globs: GlobIndex::Separate,
                })
                .is_ok()
        );
        for path in edge_paths() {
            assert_eq!(visited(&list, &path), own_results(&patterns, &path));
            assert_eq!(
                list.any_match(Some(&path)),
                !own_results(&patterns, &path).is_empty()
            );
        }
    }

    #[test]
    fn a_direct_visit_stops_at_the_first_break() {
        let patterns: Vec<_> = ["a", "*", "a/b", "b"].iter().map(|t| pattern(t)).collect();
        let index = DirectIndex::new(patterns.iter().enumerate());
        let mut seen = 0;
        let flow = index.visit(b"a/b", |_| {
            seen += 1;
            ControlFlow::Break(())
        });
        assert!(flow.is_break());
        assert_eq!(seen, 1);
        let mut all = 0;
        let flow = index.visit(b"a/b", |_| {
            all += 1;
            ControlFlow::Continue(())
        });
        assert!(flow.is_continue());
        assert!(all > 1);
    }

    fn name_strategy() -> impl Strategy<Value = String> {
        "[a-c_][a-c._]{0,2}"
    }

    fn path_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(name_strategy(), 1..4).prop_map(|parts| parts.join("/"))
    }

    proptest! {
        #[test]
        fn a_list_matches_exactly_as_its_patterns_do(
            texts in prop::collection::vec(
                prop::sample::select(vec![
                    "a", "*.tmp", "a/b", "a/*", "**/b", "*b*", "b/**/c", "**", "x[ab]?",
                    "*", "*b", "*ab", "x", "./x", "a/b/c", "a", "*b",
                ]),
                0..8,
            ),
            parts in prop::collection::vec(
                prop::sample::select(vec![
                    "a", "b", "c", "xa1", "q.tmp", ".", "..", "", "x", "ab", "xab",
                ]),
                0..5,
            ),
            leading in prop::sample::select(vec!["", "/", "./"]),
        ) {
            let patterns: Vec<_> = texts.iter().map(|text| pattern(text)).collect();
            let list = PatternList::from(patterns.clone());
            let path = format!("{leading}{}", parts.join("/"));
            let reduced = normalized(Path::new(&path));

            let mut matched = std::collections::BTreeSet::new();
            let mut scratch = Vec::new();
            list.matching(reduced.as_deref(), &mut scratch, |index| {
                matched.insert(index);
            });
            let expected: std::collections::BTreeSet<_> = patterns
                .iter()
                .enumerate()
                .filter(|(_, pattern)| pattern.matches(Path::new(&path)))
                .map(|(index, _)| index)
                .collect();
            prop_assert_eq!(&matched, &expected, "{:?} vs {:?}", texts, path);
            prop_assert_eq!(list.any_match(reduced.as_deref()), !expected.is_empty());
        }

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
        fn engines_agree_on_odd_paths(
            text in prop::sample::select(vec![".git", "*.tmp", "a", "a/b", "target/", "**", "*", "a/*"]),
            parts in prop::collection::vec(prop::sample::select(vec!["a", "b", ".", "..", "", "a.tmp"]), 0..5),
            leading in prop::sample::select(vec!["", "/", "./"]),
        ) {
            let path = format!("{leading}{}", parts.join("/"));
            prop_assert_eq!(
                pattern(text).matches(Path::new(&path)),
                glob_only(text).matches(Path::new(&path)),
                "{} vs {:?}", text, path
            );
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
            if let Ok(p) = EntryPattern::try_from(text.as_str())
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
            if let Ok(p) = EntryPattern::try_from(text.as_str()) {
                let again = EntryPattern::try_from(p.to_string().as_str());
                prop_assert_eq!(again.ok(), Some(p));
            }
        }
    }
}
