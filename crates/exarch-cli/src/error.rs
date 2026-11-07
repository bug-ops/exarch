//! Error conversion utilities for CLI.
//!
//! Converts exarch-core's typed errors (thiserror) into user-friendly
//! contextual errors (anyhow) with actionable guidance.
//!
//! CLI-authored messages are structured ([`Part`]) rather than preformatted
//! strings: escaping is a property of the output medium, so the human
//! formatter escapes archive-derived parts for the terminal while `--json`
//! keeps them exact.

use crate::cli::ZipConsistencyArg;
use crate::cli::solid_ratio_text;
use crate::operation::Flag;
use crate::operation::Operation;
use crate::output::skip_breakdown_lines;
use crate::output::terminal::TerminalEntry;
use crate::output::terminal::TerminalPath;
use crate::output::terminal::TerminalText;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ArchiveType;
use exarch_core::CompressionRatio;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::ExtractionReport;
use exarch_core::PartialWrites;
use exarch_core::PathComponentName;
use exarch_core::PolicySetting;
use exarch_core::QuotaKind;
use exarch_core::ReplaceFailure;
use exarch_core::Restore;
use exarch_core::SecurityConfig;
use exarch_core::TarTrailerRefusal;
use exarch_core::Violation;
use exarch_core::ZipBombDetails;
use exarch_core::ZipBombScope;
use exarch_core::path_text;
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// One piece of a CLI-authored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Text written in the source: trusted, may span lines.
    Lit(&'static str),
    /// A path of the host (an archive, a destination, an output), in its
    /// native spelling: escaped for the terminal, exact in `--json`.
    Path(PathBuf),
    /// The name of an archive entry: rendered injectively with `path_text`
    /// and escaped for the terminal.
    Entry(PathBuf),
    /// Single-line text, possibly derived from an archive: escaped for the
    /// terminal, exact in `--json`.
    Text(String),
}

impl Part {
    fn write_raw(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lit(text) => f.write_str(text),
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Entry(path) => f.write_str(&path_text(path)),
            Self::Text(text) => f.write_str(text),
        }
    }

    fn write_terminal(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lit(text) => f.write_str(text),
            Self::Path(path) => write!(f, "{}", TerminalPath::new(path)),
            Self::Entry(path) => write!(f, "{}", TerminalEntry::new(path)),
            Self::Text(text) => write!(f, "{}", TerminalText::new(text)),
        }
    }
}

/// The parts of a message, rendered raw for logs and `--json` or escaped for
/// a terminal.
pub struct Rendered<'a> {
    parts: &'a [Part],
    medium: Medium,
}

#[derive(Clone, Copy)]
enum Medium {
    Raw,
    Terminal,
}

impl fmt::Display for Rendered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.parts.iter().try_for_each(|part| match self.medium {
            Medium::Raw => part.write_raw(f),
            Medium::Terminal => part.write_terminal(f),
        })
    }
}

/// An error object whose text is a list of [`Part`]s.
pub trait CliMessage {
    /// The message, without its hint.
    fn parts(&self) -> Cow<'_, [Part]>;

    /// The advice that follows the message, if any.
    fn hint(&self) -> Option<Cow<'_, [Part]>>;
}

/// `link` as one of the CLI's own error objects.
fn as_cli_message<'a>(link: &'a (dyn std::error::Error + 'static)) -> Option<&'a dyn CliMessage> {
    link.downcast_ref::<CliContext>()
        .map(|c| c as &dyn CliMessage)
        .or_else(|| {
            link.downcast_ref::<PartialExtractionContext>()
                .map(|c| c as &dyn CliMessage)
        })
}

/// The structured message of `link` when it is one of the CLI's own error
/// objects.
pub fn cli_message<'a>(link: &'a (dyn std::error::Error + 'static)) -> Option<Cow<'a, [Part]>> {
    as_cli_message(link).map(CliMessage::parts)
}

/// The links of `error`'s chain that add text: the cause of a message that
/// restates it is left out.
pub fn visible_chain(error: &anyhow::Error) -> Vec<&(dyn std::error::Error + 'static)> {
    let mut links = Vec::new();
    let mut skip_cause = false;
    for link in error.chain() {
        if std::mem::take(&mut skip_cause) {
            continue;
        }
        skip_cause = link
            .downcast_ref::<CliContext>()
            .is_some_and(|context| context.restates_source);
        links.push(link);
    }
    links
}

/// The hints of every link of `error`'s chain, outermost first, each rendered
/// by `render`.
pub fn chain_hints(error: &anyhow::Error, render: fn(&[Part]) -> String) -> Vec<String> {
    error
        .chain()
        .filter_map(as_cli_message)
        .filter_map(CliMessage::hint)
        .map(|hint| render(&hint))
        .collect()
}

/// Renders `parts` with archive-derived parts escaped for a terminal.
pub fn terminal(parts: &[Part]) -> String {
    Rendered {
        parts,
        medium: Medium::Terminal,
    }
    .to_string()
}

/// Renders `parts` exactly, as `--json` and `Display` do.
pub fn raw(parts: &[Part]) -> String {
    Rendered {
        parts,
        medium: Medium::Raw,
    }
    .to_string()
}

/// Builder for one message: its parts and, apart from them, the advice that
/// follows it.
///
/// The hint is kept out of the parts so that an error chain renders as
/// `message: cause` with the hints printed last, never in the middle.
#[derive(Debug, Default)]
pub struct Message {
    parts: Vec<Part>,
    hint: Option<Vec<Part>>,
    restates_source: bool,
}

impl Message {
    /// Appends text written in the source, which may span lines.
    pub fn lit(mut self, text: &'static str) -> Self {
        self.parts.push(Part::Lit(text));
        self
    }

    /// Appends a host path (an archive, a destination), escaped for a terminal
    /// and exact in `--json`.
    pub fn path(mut self, path: &Path) -> Self {
        self.parts.push(Part::Path(path.to_path_buf()));
        self
    }

    /// Appends the name of an archive entry, rendered injectively.
    pub fn entry(mut self, path: &Path) -> Self {
        self.parts.push(Part::Entry(path.to_path_buf()));
        self
    }

    /// Appends single-line text that may derive from an archive, escaped for a
    /// terminal and exact in `--json`.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.parts.push(Part::Text(text.into()));
        self
    }

    /// Sets the advice that follows the message, when there is any to give.
    pub fn hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint.map(|body| vec![Part::Text(body)]);
        self
    }

    /// Sets the advice to text written in the source.
    pub fn hint_lit(mut self, hint: &'static str) -> Self {
        self.hint = Some(vec![Part::Lit(hint)]);
        self
    }

    /// Marks the message as already saying everything its cause says, so a
    /// rendered chain leaves the cause out.
    pub const fn restating_source(mut self) -> Self {
        self.restates_source = true;
        self
    }

    /// The message with no cause behind it.
    pub fn into_context(self) -> CliContext {
        CliContext {
            parts: self.parts,
            hint: self.hint,
            restates_source: self.restates_source,
            source: None,
        }
    }

    /// The message layered over `source`.
    fn wrapping(self, source: ArchiveError) -> CliContext {
        CliContext {
            source: Some(source),
            ..self.into_context()
        }
    }
}

/// Joins flag names as "A", "A or B" or "A, B, or C".
fn join_or(flags: &[&str]) -> String {
    match flags {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [a, b] => format!("{a} or {b}"),
        [init @ .., last] => format!("{}, or {last}", init.join(", ")),
    }
}

/// The flags of `candidates` that `op` accepts, as typed.
fn accepted(op: Operation, candidates: &[Flag]) -> Vec<&'static str> {
    candidates
        .iter()
        .filter(|flag| op.accepts(**flag))
        .map(|flag| flag.long())
        .collect()
}

fn zip_bomb_hint(op: Operation, details: &ZipBombDetails) -> Option<String> {
    if details.ratio() == CompressionRatio::Unbounded {
        return Some(
            "The archive claims data from zero compressed bytes, so its size metadata is \
             inconsistent and no ratio limit admits it."
                .to_owned(),
        );
    }
    dedicated_zip_bomb_hint(op, details.scope())
}

/// The hint for each zip-bomb scope; `None` for a scope added to the
/// `#[non_exhaustive]` [`ZipBombScope`] after this match was written, which
/// `every_zip_bomb_scope_has_a_dedicated_hint` rejects.
fn dedicated_zip_bomb_hint(op: Operation, scope: ZipBombScope) -> Option<String> {
    let ratio = op
        .accepts(Flag::MaxCompressionRatio)
        .then(|| Flag::MaxCompressionRatio.long());
    match scope {
        ZipBombScope::SolidBlock => Some(format!(
            "Solid 7z blocks use a fixed {} limit that the CLI cannot change.",
            solid_ratio_text()
        )),
        ZipBombScope::SkippedEntries => ratio.map(|flag| {
            format!(
                "Skipped entries of a compressed TAR decoded more than {flag} x the compressed \
                 input read so far (all entries); raise the ratio if legitimate."
            )
        }),
        ZipBombScope::Entry => ratio.map(|flag| {
            format!("{flag} allows higher ratios for ZIP and non-solid 7z if legitimate.")
        }),
        _ => None,
    }
}

/// CLI-authored message layered over an optional [`ArchiveError`].
///
/// A distinct error type, not an anyhow `.context()` string, so the human
/// formatter can recognise it in the error chain and escape its parts for the
/// terminal. `Display` is the message rendered exactly, without its hint; the
/// wrapped error is exposed as the `source`, so `{:#}` renders
/// `message: error`.
#[derive(Debug)]
pub struct CliContext {
    parts: Vec<Part>,
    hint: Option<Vec<Part>>,
    restates_source: bool,
    source: Option<ArchiveError>,
}

impl CliMessage for CliContext {
    fn parts(&self) -> Cow<'_, [Part]> {
        Cow::Borrowed(&self.parts)
    }

    fn hint(&self) -> Option<Cow<'_, [Part]>> {
        self.hint.as_deref().map(Cow::Borrowed)
    }
}

impl fmt::Display for CliContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            Rendered {
                parts: &self.parts,
                medium: Medium::Raw,
            }
        )
    }
}

impl std::error::Error for CliContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Carrier for partial-extraction progress embedded in the anyhow error chain.
///
/// `ArchiveError::PartialExtraction` uses `#[error("{source}")]` with
/// `#[source]`, so placing it directly in an anyhow chain causes the inner
/// error text to appear twice in `{:#}` output (once via Display, once via the
/// source chain).  This type carries the report without re-emitting the inner
/// error text in its own Display, keeping the anyhow chain clean. The
/// converted inner error is its `source`.
#[derive(Debug)]
pub struct PartialExtractionContext {
    pub(crate) report: ExtractionReport,
    pub(crate) writes: PartialWrites,
    leftover: Option<PathBuf>,
    inner: anyhow::Error,
}

impl PartialExtractionContext {
    /// The text for each [`PartialWrites`] state; `None` for a state added to
    /// the `#[non_exhaustive]` enum after this match was written, which
    /// `every_partial_writes_state_has_dedicated_text` rejects.
    fn dedicated_message(&self) -> Option<Message> {
        let r = &self.report;
        let message = match self.writes {
            PartialWrites::Kept => {
                let items = r.files_extracted + r.directories_created + r.symlinks_created;
                let mut message = Message::default()
                    .lit("WARNING: Extraction was stopped. ")
                    .text(format!(
                        "{items} items ({} files, {} directories, {} symlinks)",
                        r.files_extracted, r.directories_created, r.symlinks_created,
                    ))
                    .lit(" were written to disk before the error.");
                if r.files_skipped() > 0 {
                    message = message
                        .lit("\nFiles skipped: ")
                        .text(r.files_skipped().to_string());
                    for line in skip_breakdown_lines(&r.skipped) {
                        message = message.lit("\n").text(line);
                    }
                }
                if !r.warnings.is_empty() {
                    message = message.lit("\nWarnings:");
                    for warning in &r.warnings {
                        message = message.lit("\n  - ").text(warning.to_string());
                    }
                }
                message.hint_lit("Inspect or remove the output directory before re-running.")
            }
            // The counts and warnings describe the discarded run, not the
            // destination.
            PartialWrites::RolledBack => self.leftover.as_deref().map_or_else(
                || {
                    Message::default().lit(
                        "WARNING: Extraction was stopped. The partial extraction was discarded; \
                         the destination was left unchanged.",
                    )
                },
                |leftover| {
                    Message::default()
                        .lit(
                            "WARNING: Extraction was stopped. Nothing was published and the \
                             destination was left unchanged, but the staging directory remains \
                             at ",
                        )
                        .path(leftover)
                        .lit(".")
                        .hint_lit("Remove the staging directory when you no longer need it.")
                },
            ),
            PartialWrites::Discarded => {
                Message::default().lit("WARNING: Extraction was stopped. Nothing was written.")
            }
            _ => return None,
        };
        Some(message)
    }

    fn message(&self) -> Message {
        self.dedicated_message()
            .unwrap_or_else(|| Message::default().lit("WARNING: Extraction was stopped."))
    }
}

impl CliMessage for PartialExtractionContext {
    fn parts(&self) -> Cow<'_, [Part]> {
        Cow::Owned(self.message().parts)
    }

    fn hint(&self) -> Option<Cow<'_, [Part]>> {
        self.message().hint.map(Cow::Owned)
    }
}

impl fmt::Display for PartialExtractionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&raw(&self.parts()))
    }
}

impl std::error::Error for PartialExtractionContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Joins the rendered links of a chain: a cause follows its message after
/// `": "`, except after a partial-extraction report, which ends its own
/// sentence and is followed by the cause on a line of its own.
pub fn join_chain(
    links: &[&(dyn std::error::Error + 'static)],
    render: impl Fn(&(dyn std::error::Error + 'static)) -> String,
) -> String {
    let mut text = String::new();
    let mut previous: Option<&(dyn std::error::Error + 'static)> = None;
    for &link in links {
        if let Some(previous) = previous {
            text.push_str(if previous.is::<PartialExtractionContext>() {
                "\n"
            } else {
                ": "
            });
        }
        text.push_str(&render(link));
        previous = Some(link);
    }
    text
}

/// The visible links of `error`'s chain joined by [`join_chain`], exactly as
/// spelled.
pub fn chain_text(error: &anyhow::Error) -> String {
    join_chain(&visible_chain(error), ToString::to_string)
}

/// What a destination conflict tells the user to do, which depends on the
/// write mode that met it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictAdvice {
    /// Existing files are refused: `--force` overwrites them.
    UseForce,
    /// `--force` is already on, and a file cannot be replaced by a directory.
    ForceCannotReplace,
}

impl ConflictAdvice {
    fn hint(self) -> String {
        let force = Flag::Force.long();
        match self {
            Self::UseForce => format!("Use {force} to overwrite."),
            Self::ForceCannotReplace => format!(
                "{force} cannot replace a file with a directory; remove the listed files or \
                 choose another destination."
            ),
        }
    }
}

/// Maximum number of conflicting destination paths listed individually in a
/// conflict message before the remainder is collapsed into a single
/// "... and N more" line.
const MAX_LISTED_CONFLICTS: usize = 10;

/// The message for a destination that holds paths the archive would write.
///
/// Caps the individually listed paths at [`MAX_LISTED_CONFLICTS`] so an
/// archive with many same-named pre-existing files (up to `max_file_count`)
/// cannot flood stderr with one line per conflict. `conflicts` arrives in the
/// order core sorts it, so "first N shown" is the head of `error.conflicts`.
///
/// The advice that depends on the write mode is the message's hint, never part
/// of its text.
fn occupied_message(destination: &Path, conflicts: &[PathBuf], advice: ConflictAdvice) -> Message {
    let count = conflicts.len();
    let noun = if count == 1 { "file" } else { "files" };
    let verb = if count == 1 { "exists" } else { "exist" };

    let remaining = count.saturating_sub(MAX_LISTED_CONFLICTS);
    let mut message = if remaining == 0 {
        Message::default()
            .restating_source()
            .text(format!("{count} destination {noun} already {verb}:"))
    } else {
        Message::default().restating_source().text(format!(
            "{count} destination {noun} already {verb}; first {MAX_LISTED_CONFLICTS} shown:"
        ))
    };
    // The destination keeps its native spelling; the entry part is rendered
    // the way the archive names it.
    let destination = destination.join("");
    for path in conflicts.iter().take(MAX_LISTED_CONFLICTS) {
        message = message.lit("\n  ").path(&destination).entry(path);
    }
    if remaining > 0 {
        message = message
            .lit("\n  ... and ")
            .text(remaining.to_string())
            .lit(" more");
    }
    message.hint(Some(advice.hint()))
}

/// `text` with its first letter in upper case.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_default(|first| first.to_uppercase().chain(chars).collect())
}

/// The message for a replace of the destination that failed part-way; the
/// core error text names the paths, the hint says what to do about them.
fn replace_failed_context(message: Message, failure: &ReplaceFailure) -> Message {
    let message = message
        .restating_source()
        .text(capitalized(&failure.to_string()));
    match (&failure.restore, &failure.leftover) {
        (Restore::Failed { .. }, _) => message.hint_lit(
            "The original destination was moved aside and could not be put back; its content is \
             at the backup path named above.",
        ),
        (_, Some(_)) => message.hint_lit(
            "The original destination is intact. Remove the staging directory named above when \
             you no longer need it.",
        ),
        (_, None) => message,
    }
}

/// The advice for a refused configuration, by what was wrong with it.
fn configuration_hint(setting: ConfigSetting, problem: &ConfigProblem) -> Option<String> {
    match (setting, problem) {
        (ConfigSetting::EntrySelection, ConfigProblem::NotSupported) => {
            let force = Flag::Force.long();
            Some(format!(
                "{} {force} replaces the whole destination, so it cannot be combined with {}; \
                 drop {force} or those flags.",
                Flag::Atomic.long(),
                join_or(&[
                    Flag::Include.long(),
                    Flag::Exclude.long(),
                    Flag::StripComponents.long(),
                    Flag::Flatten.long(),
                ]),
            ))
        }
        (_, problem) => problem_hint(problem).map(str::to_owned),
    }
}

/// The advice for a refused value, by what was wrong with it.
///
/// Every [`ConfigProblem`] known today is named; a variant added to the
/// `#[non_exhaustive]` enum later gets no advice rather than a misleading
/// generic line, which `every_known_config_problem_has_advice` makes visible
/// once its fixture is added there.
fn problem_hint(problem: &ConfigProblem) -> Option<&'static str> {
    let hint = match problem {
        ConfigProblem::EntryNameCollision { .. } => {
            "Rename or exclude one of the colliding sources, or strip a different prefix."
        }
        ConfigProblem::NotADirectory | ConfigProblem::IsSymlink => {
            "Choose a destination that is a real directory, or one that does not exist yet."
        }
        ConfigProblem::ReplacesProtectedPath { .. } => "Choose a different destination directory.",
        ConfigProblem::Zero
        | ConfigProblem::Negative
        | ConfigProblem::NotFinite
        | ConfigProblem::NotWholeNumber
        | ConfigProblem::TooLarge { .. }
        | ConfigProblem::NotSet
        | ConfigProblem::NoneProvided
        | ConfigProblem::NoParent
        | ConfigProblem::NotSupported
        | ConfigProblem::CannotTargetSink
        | ConfigProblem::RemovesWholeName { .. }
        | ConfigProblem::NotAtStart
        | ConfigProblem::Empty
        | ConfigProblem::BlankOrControl
        | ConfigProblem::PaddedWithBlank
        | ConfigProblem::ContainsSeparator
        | ConfigProblem::InnerDot
        | ConfigProblem::DotEntry
        | ConfigProblem::NotOneOf { .. }
        | ConfigProblem::NotCreatable { .. }
        | ConfigProblem::TooLong { .. }
        | ConfigProblem::ContainsNul
        | ConfigProblem::ExcludePatternRefused { .. } => {
            "Check the flags you passed and their allowed value ranges."
        }
        _ => return None,
    };
    Some(hint)
}

/// The hint for a `SecurityViolation` that `relaxable_by` names.
///
/// With no `SecurityConfig` value to relax it, or no flag of `op` for one,
/// the hint says so instead of naming a flag that does not exist.
fn relaxation_hint(op: Operation, relaxable_by: Option<PolicySetting>) -> String {
    let trusted = |flag: Flag| {
        op.accepts(flag).then(|| {
            format!(
                "If this archive is from a trusted source, pass {}.",
                flag.long()
            )
        })
    };
    let hint = match relaxable_by {
        None => {
            return "This archive was rejected by a security check that cannot be relaxed via any \
                    policy flag."
                .to_owned();
        }
        Some(PolicySetting::Symlinks) => trusted(Flag::AllowSymlinks),
        Some(PolicySetting::Hardlinks) => trusted(Flag::AllowHardlinks),
        Some(PolicySetting::SolidArchives) => trusted(Flag::AllowSolidArchives),
        Some(PolicySetting::BannedComponents) => op.accepts(Flag::BannedComponent).then(|| {
            format!(
                "{} replaces the whole default list. To keep the other bans, re-pass the \
                 entries you still want banned (defaults: {}), leaving out only the component \
                 that refused this entry.",
                Flag::BannedComponent.long(),
                SecurityConfig::default()
                    .banned_path_components
                    .iter()
                    .map(PathComponentName::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }),
        Some(PolicySetting::MaxPathDepth) => op.accepts(Flag::MaxPathDepth).then(|| {
            format!(
                "If this archive is from a trusted source, pass a larger {}.",
                Flag::MaxPathDepth.long()
            )
        }),
        Some(PolicySetting::WindowsReservedNames) => {
            return "No CLI flag relaxes this. Rust API only: \
                    SecurityConfig::with_allow_windows_reserved_names."
                .to_owned();
        }
        Some(PolicySetting::MaxTarMetadataBytes) => {
            return "No CLI flag relaxes this. Rust API only: \
                    SecurityConfig::with_max_tar_metadata_bytes."
                .to_owned();
        }
        Some(_) => {
            return "Relax the SecurityConfig setting that refused this entry.".to_owned();
        }
    };
    hint.unwrap_or_else(|| {
        format!(
            "`{}` has no flag that relaxes this check; run `extract` with the matching flag.",
            op.name()
        )
    })
}

/// The archive formats the detector accepts, as canonical extensions.
fn supported_formats() -> String {
    ArchiveType::ALL
        .iter()
        .map(|t| t.extension())
        .collect::<Vec<_>>()
        .join(", ")
}

fn quota_exceeded_context(op: Operation, kind: QuotaKind, archive: &Path) -> Message {
    dedicated_quota_context(op, kind, archive).unwrap_or_else(|| {
        Message::default()
            .lit("Extraction limit exceeded for '")
            .path(archive)
            .lit("'\nNo CLI flag is known to relax it.")
    })
}

/// The context for each quota dimension; `None` only for a dimension added to
/// the `#[non_exhaustive]` [`QuotaKind`] after this match was written, which
/// `test_every_quota_kind_has_a_dedicated_context` rejects.
fn dedicated_quota_context(op: Operation, kind: QuotaKind, archive: &Path) -> Option<Message> {
    let message = Message::default();
    let context = match kind {
        QuotaKind::FileCount | QuotaKind::TotalSize | QuotaKind::FileSize => {
            let flags = accepted(op, &[Flag::MaxFiles, Flag::MaxTotalSize, Flag::MaxFileSize]);
            message
                .lit("Extraction limit exceeded for '")
                .path(archive)
                .lit("'")
                .hint((!flags.is_empty()).then(|| {
                    format!("Use {} to increase limits.", join_or(&flags))
                }))
        }
        QuotaKind::DecoderMemory => message
            .lit("Decoder memory limit exceeded for '")
            .path(archive)
            .lit(
                "'\nThe archive declares a decompression dictionary or window larger than the \
                 allowed limit. For a 7z archive, a header too large for the permitted file count \
                 is refused the same way, and --max-files raises that cap. No CLI flag relaxes \
                 the memory limit itself. Rust API only: SecurityConfig::with_max_decoder_memory.",
            ),
        QuotaKind::CompressedMembers => message
            .lit("Compressed member limit exceeded for '")
            .path(archive)
            .lit(
                "'\nThe stream holds more gzip or bzip2 members than its output allows. No CLI \
                 flag relaxes this. Rust API only: SecurityConfig::with_compressed_member_allowance.",
            ),
        QuotaKind::IntegerOverflow => message
            .lit("Quota accounting overflowed for '")
            .path(archive)
            .lit(
                "'\nThe archive declares sizes or counts too large to track. No CLI flag relaxes \
                 this.",
            ),
        QuotaKind::TreeNodes => message
            .lit("Destination name budget exceeded for '")
            .path(archive)
            .lit(
                "'\nThe archive spells more distinct names than the in-memory destination model \
                 admits. No CLI flag relaxes this. Rust API only: \
                 SecurityConfig::with_max_file_count and SecurityConfig::with_max_path_depth.",
            ),
        QuotaKind::SinkCapacity => message
            .lit("In-memory sink capacity exceeded for '")
            .path(archive)
            .lit("'\nNo CLI flag relaxes this. Rust API only: the sink's capacity limit."),
        QuotaKind::SolidBlockMemory => message
            .lit("Solid block size limit exceeded for '")
            .path(archive)
            .lit(
                "'\nA solid 7z block declares more decoded data than the limit admits. No CLI \
                 flag relaxes this. Rust API only: SecurityConfig::with_solid_limits.",
            ),
        _ => return None,
    };
    Some(context)
}

/// Converts an `ArchiveError` met while running `op` to a user-friendly anyhow
/// error with context.
///
/// The original `ArchiveError` is preserved as the source of a [`CliContext`]
/// so that callers can downcast via the anyhow chain (used by JSON error
/// output). Hints name only flags `op` accepts.
///
/// A `PartialExtraction` keeps the `writes` outcome core recorded.
pub fn convert_error(op: Operation, err: ArchiveError, archive: &Path) -> anyhow::Error {
    convert_error_with_advice(op, err, archive, ConflictAdvice::UseForce)
}

/// [`convert_error`] with the advice a destination conflict gets, for a
/// caller that knows which write mode produced it.
pub fn convert_error_with_advice(
    op: Operation,
    err: ArchiveError,
    archive: &Path,
    advice: ConflictAdvice,
) -> anyhow::Error {
    // `PartialExtraction` is `#[error("{source}")]` with `#[source]`, so
    // placing it in an anyhow chain directly would cause the inner error text
    // to appear twice in `{:#}` output. Converting the inner `source` first
    // gives it its own fully-formed, category-specific context (HINT
    // included); `PartialExtractionContext` is then layered on top as an
    // additional context frame, which never re-displays the inner error text.
    //
    // This keeps issue #204's "inner error text appears exactly once in
    // `{:#}`" guarantee: no CLI-authored context below interpolates data the
    // wrapped error's own Display already carries.
    let err = match err {
        ArchiveError::PartialExtraction(partial) => {
            let leftover = partial.leftover().map(|leftover| leftover.path.clone());
            let (cause, report, writes) = partial.into_parts();
            return anyhow::Error::new(PartialExtractionContext {
                report,
                writes,
                leftover,
                inner: convert_error_with_advice(op, cause, archive, advice),
            });
        }
        other => other,
    };

    let context = context_message(op, &err, archive, advice);
    anyhow::Error::new(context.wrapping(err))
}

fn zip_inconsistency_message(op: Operation, message: Message, archive: &Path) -> Message {
    let relax = op.accepts(Flag::ZipConsistency).then(|| {
        format!(
            " Use {} {} only for archives from a trusted producer.",
            Flag::ZipConsistency.long(),
            ZipConsistencyArg::Ignore.value_name()
        )
    });
    message
        .lit("Security violation: ZIP archive '")
        .path(archive)
        .lit("' is read differently by different tools")
        .hint(Some(format!(
            "The archive may be crafted to show different content to different \
             extractors.{}",
            relax.unwrap_or_default()
        )))
}

/// The message for `err`; the generic one for a variant added to
/// `ArchiveError` after [`dedicated_context`] was written.
fn context_message(
    op: Operation,
    err: &ArchiveError,
    archive: &Path,
    advice: ConflictAdvice,
) -> Message {
    dedicated_context(op, err, archive, advice).unwrap_or_else(|| {
        Message::default()
            .lit("Error while processing '")
            .path(archive)
            .lit("'")
    })
}

fn source_not_found_context(op: Operation, path: &Path, message: Message) -> Message {
    let message = message
        .restating_source()
        .lit("Source path not found: ")
        .path(path);
    message.hint_lit(match op {
        Operation::Create => "Verify the source path exists and is readable.",
        Operation::Extract | Operation::List | Operation::Verify => {
            "Verify the archive path exists and is readable."
        }
    })
}

fn source_not_accessible_context(
    op: Operation,
    path: &Path,
    error: &io::Error,
    message: Message,
) -> Message {
    let message = message
        .restating_source()
        .lit("Source path is not accessible: ")
        .path(path)
        .text(format!(": {error}"));
    if error.kind() != io::ErrorKind::PermissionDenied {
        return message;
    }
    message.hint_lit(match op {
        Operation::Create => "Check file permissions on the source.",
        Operation::Extract | Operation::List | Operation::Verify => {
            "Check file permissions on the archive."
        }
    })
}

/// The advice of a refusal that has some of its own; `None` for every other
/// kind, which gets the generic relaxation hint.
fn refusal_hint(kind: &Violation) -> Option<String> {
    match kind {
        Violation::HardlinkTargetNotExtracted { .. } => Some(format!(
            "Select the link's target as well ({}), strip fewer components, or leave the link \
             out ({}); no flag relaxes this check.",
            Flag::Include.long(),
            Flag::Exclude.long(),
        )),
        Violation::LinkUnderFlatten { .. } => Some(format!(
            "Leave links out with {}, or extract without {}.",
            Flag::Exclude.long(),
            Flag::Flatten.long(),
        )),
        Violation::DestinationChanged => Some(
            "Another process modified the destination during the replace, so nothing was \
             replaced. Re-run once the destination is no longer in use."
                .to_owned(),
        ),
        _ => None,
    }
}

fn security_violation(message: Message, archive: &Path, hint: String) -> Message {
    message
        .lit("Security violation while processing '")
        .path(archive)
        .lit("'")
        .hint(Some(hint))
}

/// The message of each known `ArchiveError` variant; `None` for a variant
/// added after this match was written, which
/// `every_archive_error_has_a_dedicated_context` rejects.
fn dedicated_context(
    op: Operation,
    err: &ArchiveError,
    archive: &Path,
    advice: ConflictAdvice,
) -> Option<Message> {
    let message = Message::default();
    Some(match err {
        ArchiveError::PathTraversal { .. } => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit("' attempted path traversal")
            .hint_lit("This archive may be malicious. Do not extract from untrusted sources."),
        ArchiveError::ZipBomb(details) => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit("' appears to be a zip bomb")
            .hint(zip_bomb_hint(op, details)),
        ArchiveError::ZipInconsistency(_) => zip_inconsistency_message(op, message, archive),
        ArchiveError::QuotaExceeded { resource } => {
            quota_exceeded_context(op, resource.kind(), archive)
        }
        ArchiveError::SymlinkEscape { .. } | ArchiveError::HardlinkEscape { .. } => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit("' has a link that escapes the destination")
            .hint_lit(
                "a link resolves outside the destination (an archive link or an existing \
                 destination symlink); no flag relaxes this check.",
            ),
        ArchiveError::Io(_) => message.lit("Failed to process '").path(archive).lit("'"),
        ArchiveError::UnknownFormat { .. } => message
            .lit("Cannot determine archive format")
            .hint(Some(format!("Supported formats: {}", supported_formats()))),
        ArchiveError::UnmatchedInclude { .. } => message
            .lit("No entry of '")
            .path(archive)
            .lit("' matches an ")
            .lit(Flag::Include.long())
            .lit(" pattern")
            .hint(Some(format!(
                "Patterns match the entry path as the archive lists it, before {}; run `exarch \
                 list` to see the names.",
                Flag::StripComponents.long()
            ))),
        ArchiveError::SecurityViolation { kind, .. } => security_violation(
            message,
            archive,
            refusal_hint(kind).unwrap_or_else(|| relaxation_hint(op, err.relaxable_by())),
        ),
        ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { .. }) => {
            security_violation(message, archive, relaxation_hint(op, err.relaxable_by()))
        }
        ArchiveError::InvalidArchive(_)
        | ArchiveError::TarAmbiguity(_)
        | ArchiveError::TarTrailer(_) => message
            .lit("Invalid archive '")
            .path(archive)
            .lit("'")
            .hint_lit("The archive may be corrupted or malformed."),
        ArchiveError::InvalidConfiguration { setting, problem } => message
            .text(format!("Cannot {} with these settings", op.name()))
            .hint(configuration_hint(*setting, problem)),
        ArchiveError::SourceNotFound { path } => source_not_found_context(op, path, message),
        ArchiveError::SourceNotAccessible { path, error } => {
            source_not_accessible_context(op, path, error, message)
        }
        ArchiveError::OutputExists { path } => message
            .restating_source()
            .lit("Output path already exists: ")
            .path(path)
            .hint(
                op.accepts(Flag::Force)
                    .then(|| format!("Use {} to overwrite.", Flag::Force.long())),
            ),
        ArchiveError::DestinationOccupied {
            destination,
            conflicts,
        } => occupied_message(destination, conflicts, advice),
        ArchiveError::InvalidPermissions { mode, .. } => message.text(format!(
            "Invalid permissions {:#o}: blocked by security policy.",
            mode.get()
        )),
        ArchiveError::InvalidCompressionLevel { level } => message.text(format!(
            "Invalid compression level {level}: must be between 1 and 9."
        )),

        ArchiveError::Cancelled => message.lit("Operation cancelled"),
        ArchiveError::OutputReservationLeft { .. } => {
            message.lit("Failed to finish writing the output")
        }
        ArchiveError::ReplaceFailed(failure) => replace_failed_context(message, failure),

        ArchiveError::ReaderFormat(_) => message
            .lit("Cannot use the format of '")
            .path(archive)
            .lit("'"),

        // `#[non_exhaustive]` requires this arm to compile against a newer
        // exarch-core.
        _ => return None,
    })
}

/// The staging directory or reservation file that a failed run left behind and
/// `error` names, as the CLI reports paths: unredacted.
pub fn leftover_path(error: &anyhow::Error) -> Option<&Path> {
    if let Some(context) = error.downcast_ref::<PartialExtractionContext>() {
        return context.leftover.as_deref();
    }
    error
        .chain()
        .find_map(|link| match link.downcast_ref::<ArchiveError>()? {
            ArchiveError::ReplaceFailed(failure) => failure
                .leftover
                .as_ref()
                .map(|leftover| leftover.path.as_path()),
            ArchiveError::OutputReservationLeft { path, .. } => Some(path.as_path()),
            _ => None,
        })
}

/// Whether `error` is the cancellation of a run (a stop asked for through the
/// progress callback), whether or not it stopped part-way.
pub fn is_cancelled(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|link| link.downcast_ref::<ArchiveError>())
        .any(ArchiveError::is_cancelled)
}

/// Adds context to a generic error about archive operations.
pub fn add_archive_context<T>(
    op: Operation,
    result: Result<T, ArchiveError>,
    archive: &Path,
) -> anyhow::Result<T> {
    result.map_err(|e| convert_error(op, e, archive))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use exarch_core::Compressed;
    use exarch_core::LinkKind;
    use exarch_core::Uncompressed;
    use exarch_core::Violation;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn every_known_config_problem_has_advice() {
        use exarch_core::ExcludeRefusal;
        use exarch_core::ExtractOnlyFormat;
        use exarch_core::ProtectedPath;

        let problems = [
            ConfigProblem::Zero,
            ConfigProblem::Negative,
            ConfigProblem::NotFinite,
            ConfigProblem::NotWholeNumber,
            ConfigProblem::TooLarge { max: 1 },
            ConfigProblem::NotSet,
            ConfigProblem::NoneProvided,
            ConfigProblem::NoParent,
            ConfigProblem::NotSupported,
            ConfigProblem::CannotTargetSink,
            ConfigProblem::RemovesWholeName { path: "a".into() },
            ConfigProblem::NotAtStart,
            ConfigProblem::Empty,
            ConfigProblem::BlankOrControl,
            ConfigProblem::PaddedWithBlank,
            ConfigProblem::ContainsSeparator,
            ConfigProblem::InnerDot,
            ConfigProblem::DotEntry,
            ConfigProblem::NotOneOf { allowed: &["a"] },
            ConfigProblem::NotCreatable {
                format: ExtractOnlyFormat::SevenZ,
            },
            ConfigProblem::TooLong { max: 1, got: 2 },
            ConfigProblem::ContainsNul,
            ConfigProblem::ExcludePatternRefused {
                pattern: "p".into(),
                reason: ExcludeRefusal::Empty,
            },
            ConfigProblem::NotADirectory,
            ConfigProblem::IsSymlink,
            ConfigProblem::EntryNameCollision {
                name: "n".into(),
                first: "a".into(),
                second: "b".into(),
            },
            ConfigProblem::ReplacesProtectedPath {
                path: ProtectedPath::WorkingDirectory,
            },
        ];
        for problem in &problems {
            assert!(problem_hint(problem).is_some(), "{problem:?} has no advice");
        }
    }

    /// The message chain followed by its hints, as the terminal shows them.
    fn full_text(error: &anyhow::Error) -> String {
        let mut text = chain_text(error);
        for hint in chain_hints(error, raw) {
            text.push_str("\nHINT: ");
            text.push_str(&hint);
        }
        text
    }

    fn source_not_accessible_message(kind: io::ErrorKind) -> String {
        let err = ArchiveError::SourceNotAccessible {
            path: PathBuf::from("src/a.txt"),
            error: io::Error::from(kind),
        };
        full_text(&convert_error(Operation::Create, err, Path::new("o.tar")))
    }

    #[test]
    fn the_permission_hint_is_shown_for_permission_failures_only() {
        let denied = source_not_accessible_message(io::ErrorKind::PermissionDenied);
        assert!(denied.contains("Check file permissions"), "{denied}");
        for kind in [io::ErrorKind::Other, io::ErrorKind::TimedOut] {
            let other = source_not_accessible_message(kind);
            assert!(other.contains("Source path is not accessible"), "{other}");
            assert!(!other.contains("permissions"), "{other}");
        }
    }

    #[test]
    fn test_convert_path_traversal_error() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../../../etc/passwd"),
        };
        let converted = convert_error(Operation::Extract, err, Path::new("malicious.zip"));
        let msg = full_text(&converted);
        assert!(msg.contains("path traversal"));
        assert!(msg.contains("malicious.zip"));
        assert!(msg.contains("HINT"));
    }

    fn zip_bomb_message(scope: ZipBombScope, compressed: u64, uncompressed: u64) -> String {
        let err = ArchiveError::ZipBomb(ZipBombDetails::new(
            scope,
            Compressed(compressed),
            Uncompressed(uncompressed),
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("bomb.zip"));
        full_text(&converted)
    }

    #[test]
    fn test_convert_zip_bomb_error() {
        let msg = zip_bomb_message(ZipBombScope::Entry, 1024, 1024 * 1024 * 150);
        assert!(msg.contains("zip bomb"));
        assert!(msg.contains("bomb.zip"));
        assert!(msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_zip_bomb_solid_block_hint() {
        let msg = zip_bomb_message(ZipBombScope::SolidBlock, 1024, 1024 * 1024 * 150);
        assert!(msg.contains("fixed 1000x limit"));
        assert!(!msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_zip_bomb_skipped_entries_hint() {
        let msg = zip_bomb_message(ZipBombScope::SkippedEntries, 1024, 1024 * 1024 * 150);
        assert!(msg.contains("Skipped entries of a compressed TAR"));
        assert!(msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_zip_bomb_unbounded_hint() {
        let msg = zip_bomb_message(ZipBombScope::Entry, 0, 10);
        assert!(msg.contains("size metadata is inconsistent"));
        assert!(!msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_path_traversal_path_appears_once() {
        let path = PathBuf::from("../../../etc/passwd");
        let err = ArchiveError::PathTraversal { path };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert_eq!(
            msg.matches("../../../etc/passwd").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_symlink_escape_path_appears_once() {
        let path = PathBuf::from("link/to/escape");
        let err = ArchiveError::SymlinkEscape { path };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert_eq!(
            msg.matches("link/to/escape").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_link_escape_hint_states_no_flag_relaxes_it() {
        for err in [
            ArchiveError::SymlinkEscape {
                path: PathBuf::from("link/to/escape"),
            },
            ArchiveError::HardlinkEscape {
                path: PathBuf::from("hard/link/escape"),
            },
        ] {
            let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
            let msg = full_text(&converted);
            assert!(msg.contains("no flag relaxes this check"), "{msg}");
            assert!(!msg.contains("--allow-"), "{msg}");
        }
    }

    #[test]
    fn test_hardlink_escape_path_appears_once() {
        let path = PathBuf::from("hard/link/escape");
        let err = ArchiveError::HardlinkEscape { path };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert_eq!(
            msg.matches("hard/link/escape").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_convert_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = ArchiveError::Io(io_err);
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(msg.contains("I/O error"));
    }

    // Regression test for issue #528: the `Io` arm's context must not
    // re-embed the wrapped `io::Error`'s own Display text, since anyhow's
    // `{:#}` rendering already appends the source error after the context.
    #[test]
    fn test_io_error_no_duplication() {
        let io_err = io::Error::new(
            io::ErrorKind::InvalidData,
            "Illegal byte sequence (os error 92)",
        );
        let err = ArchiveError::Io(io_err);
        let converted = convert_error(Operation::Extract, err, Path::new("nonutf8.tar"));
        let msg = full_text(&converted);
        assert_eq!(
            msg.matches("Illegal byte sequence (os error 92)").count(),
            1,
            "OS error text should appear exactly once, got: {msg}"
        );
        assert_eq!(
            msg.matches("I/O error").count(),
            1,
            "\"I/O error\" phrase should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #204: PartialExtraction wrapping
    // HardlinkEscape / SymlinkEscape must not repeat the inner error text
    // more than once.

    #[test]
    fn test_partial_hardlink_escape_inner_text_appears_once() {
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 1;
            r.directories_created = 0;
            r.symlinks_created = 0;
            r.bytes_written = 0;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(0);
            r.warnings = vec![];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        let occurrences = msg.matches("hardlink_escape_path").count();
        assert_eq!(
            occurrences, 1,
            "inner error path should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #295: four explicit arms must produce
    // actionable messages.

    #[test]
    fn test_output_exists_contains_path_and_hint() {
        let path = PathBuf::from("/tmp/output");
        let err = ArchiveError::OutputExists { path };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(msg.contains("/tmp/output"), "path missing: {msg}");
        assert!(msg.contains("--force"), "hint missing: {msg}");
    }

    #[test]
    fn test_invalid_permissions_contains_mode_and_path() {
        let path = PathBuf::from("evil/file");
        let err = ArchiveError::InvalidPermissions {
            path,
            mode: exarch_core::RawMode::new(0o4755),
        };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(msg.contains("evil/file"), "path missing: {msg}");
        assert!(
            msg.contains("security policy"),
            "policy text missing: {msg}"
        );
    }

    #[test]
    fn test_invalid_compression_level_contains_level() {
        let err = ArchiveError::InvalidCompressionLevel {
            level: exarch_core::RequestedLevel::Integer(0),
        };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(msg.contains('0'), "level missing: {msg}");
        assert!(msg.contains("between 1 and 9"), "range hint missing: {msg}");
    }

    #[test]
    fn test_security_violation_reason_appears_exactly_once() {
        let err = ArchiveError::from(Violation::EncryptedEntry {
            name: "distinctive-entry".into(),
        });
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert_eq!(
            msg.matches("distinctive-entry").count(),
            1,
            "reason should appear exactly once, got: {msg}"
        );
    }

    // Regression test for issue #520: the GHSA-5j8q-wxg5-hj4r forged-size
    // SecurityViolation must get its own accurate HINT, not the generic
    // policy-flag one, since none of those flags can fix a size mismatch.

    #[test]
    fn test_security_violation_forged_size_hint_omits_policy_flags() {
        let err = ArchiveError::from(Violation::DeclaredSizeExceeded { declared: 50 });
        let converted = convert_error(Operation::Extract, err, Path::new("archive.zip"));
        let msg = full_text(&converted);
        assert!(
            msg.contains("cannot be relaxed via any policy flag"),
            "expected the size-mismatch-specific HINT, got: {msg}"
        );
        for flag in [
            "--allow-symlinks",
            "--allow-hardlinks",
            "--allow-solid-archives",
            "--banned-component",
        ] {
            assert!(
                !msg.contains(flag),
                "forged-size HINT must not mention {flag}, got: {msg}"
            );
        }
    }

    fn violation_for(setting: PolicySetting) -> Violation {
        match setting {
            PolicySetting::Symlinks => Violation::LinksNotAllowed(LinkKind::Symlink),
            PolicySetting::Hardlinks => Violation::LinksNotAllowed(LinkKind::Hardlink),
            PolicySetting::SolidArchives => Violation::SolidArchive,
            PolicySetting::BannedComponents => Violation::BannedComponent {
                component: ".git".into(),
            },
            PolicySetting::MaxPathDepth => Violation::PathDepth { depth: 2, max: 1 },
            PolicySetting::WindowsReservedNames => Violation::ReservedDeviceName {
                component: "CON".into(),
            },
            PolicySetting::MaxTarMetadataBytes => Violation::TarMetadataBudget { limit: 1 },
            other => panic!("no sample violation for {other}"),
        }
    }

    fn hint_for(setting: PolicySetting) -> String {
        let err = ArchiveError::from(violation_for(setting));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        full_text(&converted)
    }

    #[test]
    fn test_security_violation_hint_names_exact_flag() {
        for (setting, flag) in [
            (PolicySetting::Symlinks, "--allow-symlinks"),
            (PolicySetting::Hardlinks, "--allow-hardlinks"),
            (PolicySetting::SolidArchives, "--allow-solid-archives"),
            (PolicySetting::BannedComponents, "--banned-component"),
            (PolicySetting::MaxPathDepth, "--max-path-depth"),
        ] {
            let msg = hint_for(setting);
            assert!(msg.contains(flag), "HINT missing {flag}: {msg}");
            assert!(
                !msg.contains("cannot be relaxed"),
                "relaxable HINT must not claim otherwise: {msg}"
            );
        }
    }

    #[test]
    fn test_security_violation_hint_mentions_only_its_own_flag() {
        let msg = hint_for(PolicySetting::Symlinks);
        for flag in [
            "--allow-hardlinks",
            "--allow-solid-archives",
            "--banned-component",
        ] {
            assert!(!msg.contains(flag), "unexpected {flag}: {msg}");
        }
    }

    #[test]
    fn test_banned_component_hint_renders_defaults_and_never_suggests_empty_list() {
        let msg = hint_for(PolicySetting::BannedComponents);
        let config = SecurityConfig::default();
        for default in &config.banned_path_components {
            assert!(
                msg.contains(default.as_str()),
                "default {default} missing: {msg}"
            );
        }
        assert!(
            msg.contains("replaces the whole default list"),
            "got: {msg}"
        );
        assert!(
            !msg.contains("empty"),
            "must not advertise the empty list: {msg}"
        );
    }

    #[test]
    fn test_api_only_settings_point_at_rust_api() {
        for (setting, api) in [
            (
                PolicySetting::WindowsReservedNames,
                "with_allow_windows_reserved_names",
            ),
            (
                PolicySetting::MaxTarMetadataBytes,
                "with_max_tar_metadata_bytes",
            ),
        ] {
            let msg = hint_for(setting);
            assert!(msg.contains("Rust API only"), "got: {msg}");
            assert!(msg.contains(api), "got: {msg}");
            assert!(!msg.contains("--allow"), "no CLI flag exists: {msg}");
        }
    }

    #[test]
    fn test_every_quota_kind_has_a_dedicated_context() {
        let archive = Path::new("a.tar");
        for &kind in QuotaKind::ALL {
            let msg = dedicated_quota_context(Operation::Extract, kind, archive).map_or_else(
                || panic!("{kind} took the wildcard arm"),
                |m| {
                    let context = m.into_context();
                    let hint = context.hint().map_or_default(|h| raw(&h));
                    format!("{}\nHINT: {hint}", raw(&context.parts()))
                },
            );
            let raises_a_flag = msg.contains("HINT: Use --max-files");
            let is_size_or_count = matches!(
                kind,
                QuotaKind::FileCount | QuotaKind::TotalSize | QuotaKind::FileSize
            );
            assert_eq!(
                raises_a_flag, is_size_or_count,
                "{kind} points at the wrong flags: {msg}"
            );
        }
    }

    #[test]
    fn test_every_policy_setting_has_a_specific_hint() {
        for &setting in PolicySetting::ALL {
            let msg = hint_for(setting);
            assert!(
                !msg.contains("Relax the SecurityConfig setting"),
                "{setting} fell through to the generic hint: {msg}"
            );
        }
    }

    #[test]
    fn test_partial_symlink_escape_inner_text_appears_once() {
        use std::time::Duration;

        let inner = ArchiveError::SymlinkEscape {
            path: PathBuf::from("symlink_escape_path"),
        };
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 2;
            r.directories_created = 1;
            r.symlinks_created = 0;
            r.bytes_written = 100;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(0);
            r.warnings = vec![];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        let occurrences = msg.matches("symlink_escape_path").count();
        assert_eq!(
            occurrences, 1,
            "inner error path should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #503: files_skipped/warnings must be shown in
    // the partial-extraction Display output when present, and hidden when
    // both are empty/zero (mirrors the #498-fix "shown when present" pattern).

    #[test]
    fn test_partial_display_shows_files_skipped_and_warnings_when_present() {
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 1;
            r.directories_created = 0;
            r.symlinks_created = 0;
            r.bytes_written = 0;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(2);
            r.warnings = vec![crate::test_support::extraction_warning(
                "skipped a broken symlink",
            )];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(msg.contains("Files skipped: 2"), "got: {msg}");
        assert!(msg.contains("Warnings:"), "got: {msg}");
        assert!(msg.contains("skipped a broken symlink"), "got: {msg}");
    }

    // Regression test for issue #527: PartialExtraction must not discard the
    // category-specific HINT the wrapped source would otherwise get.

    #[test]
    fn test_partial_security_violation_keeps_hint_and_partial_progress_wording() {
        use std::time::Duration;

        let inner = ArchiveError::from(Violation::LinksNotAllowed(LinkKind::Symlink));
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 3;
            r.directories_created = 1;
            r.symlinks_created = 0;
            r.bytes_written = 42;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(0);
            r.warnings = vec![];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(
            msg.contains("were written to disk before the error"),
            "partial-progress wording missing: {msg}"
        );
        assert!(
            msg.contains("--allow-symlinks"),
            "category-specific HINT missing: {msg}"
        );
        assert_eq!(
            msg.matches("symlinks not allowed").count(),
            1,
            "inner error reason should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_partial_rolled_back_display_makes_no_written_claim() {
        use std::time::Duration;

        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 1;
            r.directories_created = 0;
            r.symlinks_created = 0;
            r.bytes_written = 0;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(0);
            r.warnings = vec![];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            ArchiveError::HardlinkEscape {
                path: PathBuf::from("hardlink_escape_path"),
            },
            report,
            PartialWrites::RolledBack,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(!msg.contains("written to disk"), "got: {msg}");
        assert!(!msg.contains("Inspect or remove"), "got: {msg}");
        assert!(msg.contains("destination was left unchanged"), "got: {msg}");
        assert_eq!(msg.matches("hardlink_escape_path").count(), 1, "got: {msg}");
    }

    #[test]
    fn test_partial_rolled_back_display_omits_the_discarded_runs_skips_and_warnings() {
        use std::time::Duration;

        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 1;
            r.directories_created = 0;
            r.symlinks_created = 0;
            r.bytes_written = 0;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(3);
            r.warnings = vec![crate::test_support::extraction_warning("skipped 3 entries")];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            ArchiveError::HardlinkEscape {
                path: PathBuf::from("hardlink_escape_path"),
            },
            report,
            PartialWrites::RolledBack,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(!msg.contains("Files skipped"), "got: {msg}");
        assert!(!msg.contains("Warnings:"), "got: {msg}");
        assert!(!msg.contains("skipped 3 entries"), "got: {msg}");
        assert!(msg.contains("destination was left unchanged"), "got: {msg}");
    }

    #[test]
    fn test_partial_display_hides_files_skipped_and_warnings_when_empty() {
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 1;
            r.directories_created = 0;
            r.symlinks_created = 0;
            r.bytes_written = 0;
            r.duration = Duration::from_millis(0);
            r.skipped = crate::test_support::skips(0);
            r.warnings = vec![];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = full_text(&converted);
        assert!(!msg.contains("Files skipped"), "got: {msg}");
        assert!(!msg.contains("Warnings:"), "got: {msg}");
    }

    #[test]
    fn test_cli_context_keeps_archive_error_as_source() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../x"),
        };
        let converted = convert_error(Operation::Extract, err, Path::new("a.tar"));
        assert!(converted.downcast_ref::<CliContext>().is_some());
        assert!(
            converted
                .chain()
                .any(|link| link.downcast_ref::<ArchiveError>().is_some())
        );
    }

    #[test]
    fn test_partial_context_is_chain_root_with_inner_source() {
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            ArchiveError::PathTraversal {
                path: PathBuf::from("../x"),
            },
            ExtractionReport::default(),
            PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("a.tar"));
        assert!(
            converted
                .downcast_ref::<PartialExtractionContext>()
                .is_some()
        );
        let kinds: Vec<_> = converted
            .chain()
            .map(|link| {
                (
                    link.is::<PartialExtractionContext>(),
                    link.is::<CliContext>(),
                )
            })
            .collect();
        assert_eq!(kinds[0], (true, false));
        assert_eq!(kinds[1], (false, true));
    }

    #[test]
    fn test_invalid_archive_reason_appears_once() {
        let err = ArchiveError::from(exarch_core::Malformation::SymlinkTargetUnreadable {
            detail: "distinctive-reason".into(),
        });
        let converted = convert_error(Operation::Extract, err, Path::new("a.tar"));
        let msg = full_text(&converted);
        assert_eq!(msg.matches("distinctive-reason").count(), 1, "got: {msg}");
    }

    fn forged_warning_context() -> PartialExtractionContext {
        PartialExtractionContext {
            report: {
                let mut r = exarch_core::ExtractionReport::new();
                r.warnings = vec![crate::test_support::extraction_warning("w\x1b[31m\nforged")];
                r
            },
            writes: PartialWrites::Kept,
            leftover: None,
            inner: anyhow::anyhow!("inner"),
        }
    }

    #[test]
    fn test_partial_terminal_rendering_escapes_warnings() {
        let rendered = terminal(&forged_warning_context().parts());
        assert!(!rendered.contains('\x1b'), "got: {rendered:?}");
        assert!(
            rendered.contains("\\x1b[31m\\x0aforged"),
            "got: {rendered:?}"
        );
    }

    #[test]
    fn test_partial_display_keeps_archive_text_exact_for_json() {
        let msg = forged_warning_context().to_string();
        assert!(msg.contains("w\x1b[31m\nforged"), "got: {msg:?}");
    }

    #[test]
    fn terminal_rendering_escapes_paths_and_text_but_not_literals() {
        let message = Message::default()
            .lit("a\nb ")
            .path(Path::new("p\x1b"))
            .lit(" ")
            .text("t\x1b")
            .into_context()
            .parts()
            .into_owned();
        assert_eq!(raw(&message), "a\nb p\x1b t\x1b");
        assert_eq!(terminal(&message), "a\nb p\\x1b t\\x1b");
    }

    #[test]
    fn every_partial_writes_state_has_dedicated_text() {
        for &writes in PartialWrites::ALL {
            let context = PartialExtractionContext {
                report: ExtractionReport::default(),
                writes,
                leftover: None,
                inner: anyhow::anyhow!("inner"),
            };
            assert!(
                context.dedicated_message().is_some(),
                "{writes} took the wildcard"
            );
        }
    }

    #[test]
    fn a_kept_partial_extraction_lists_skips_per_kind() {
        let mut report = exarch_core::ExtractionReport::new();
        report.skipped = crate::test_support::skips(2);
        let context = PartialExtractionContext {
            report,
            writes: PartialWrites::Kept,
            leftover: None,
            inner: anyhow::anyhow!("inner"),
        };
        let text = context.to_string();
        assert!(
            text.contains("Files skipped: 2\n    duplicate: 2"),
            "{text}"
        );
    }

    #[test]
    fn discarded_extraction_says_nothing_was_written() {
        let context = PartialExtractionContext {
            report: ExtractionReport::default(),
            writes: PartialWrites::Discarded,
            leftover: None,
            inner: anyhow::anyhow!("inner"),
        };
        assert_eq!(
            context.to_string(),
            "WARNING: Extraction was stopped. Nothing was written."
        );
    }

    #[test]
    fn every_zip_bomb_scope_has_a_dedicated_hint() {
        for &scope in ZipBombScope::ALL {
            assert!(
                dedicated_zip_bomb_hint(Operation::Extract, scope).is_some(),
                "{scope} took the wildcard arm"
            );
        }
    }

    #[test]
    fn hints_name_only_flags_their_operation_accepts() {
        for &op in Operation::ALL {
            for err in hint_probes() {
                let converted = convert_error(op, err, Path::new("a.tar"));
                let msg = converted
                    .downcast_ref::<CliContext>()
                    .map_or_default(|c| raw(&c.parts()));
                for &flag in Flag::ALL {
                    assert!(
                        op.accepts(flag) || !msg.contains(flag.long()),
                        "{} hint names {} it does not accept: {msg}",
                        op.name(),
                        flag.long()
                    );
                }
            }
        }
    }

    /// One value of every `ArchiveError` variant `convert_error` reaches
    /// `dedicated_context` with (a `PartialExtraction` is unwrapped first).
    /// `ArchiveError` has no `ALL`, so a variant added to core needs a sample
    /// here by hand.
    #[allow(clippy::unwrap_used)]
    fn every_archive_error_variant() -> Vec<ArchiveError> {
        let path = || PathBuf::from("p");
        vec![
            ArchiveError::Io(io::Error::from(io::ErrorKind::Other)),
            ArchiveError::InvalidArchive(exarch_core::Malformation::LinkTargetMissing(
                LinkKind::Symlink,
            )),
            ArchiveError::TarAmbiguity(exarch_core::TarAmbiguity::MalformedRecord),
            ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 1 }),
            ArchiveError::PathTraversal { path: path() },
            ArchiveError::SymlinkEscape { path: path() },
            ArchiveError::HardlinkEscape { path: path() },
            ArchiveError::ZipBomb(ZipBombDetails::new(
                ZipBombScope::Entry,
                Compressed(1),
                Uncompressed(1 << 30),
            )),
            ArchiveError::ZipInconsistency(exarch_core::ZipInconsistency::OverlappingEntries),
            ArchiveError::InvalidPermissions {
                path: path(),
                mode: exarch_core::RawMode::new(0o4755),
            },
            ArchiveError::QuotaExceeded {
                resource: exarch_core::QuotaResource::FileCount { current: 2, max: 1 },
            },
            ArchiveError::from(Violation::SolidArchive),
            ArchiveError::SourceNotFound { path: path() },
            ArchiveError::SourceNotAccessible {
                path: path(),
                error: io::Error::from(io::ErrorKind::PermissionDenied),
            },
            ArchiveError::OutputExists { path: path() },
            ArchiveError::InvalidCompressionLevel {
                level: exarch_core::RequestedLevel::OutOfRange,
            },
            ArchiveError::UnknownFormat { path: path() },
            ArchiveError::ReaderFormat(exarch_core::ReaderFormatError::Unrecognized),
            ArchiveError::UnmatchedInclude {
                patterns: Box::new([exarch_core::EntryPattern::parse_for(
                    ConfigSetting::EntryInclude,
                    "a",
                )
                .unwrap()]),
            },
            ArchiveError::InvalidConfiguration {
                setting: exarch_core::ConfigSetting::OutputPath,
                problem: exarch_core::ConfigProblem::Empty,
            },
            ArchiveError::Cancelled,
            ArchiveError::DestinationOccupied {
                destination: path(),
                conflicts: Box::new([path()]),
            },
            ArchiveError::OutputReservationLeft {
                path: path(),
                error: io::Error::from(io::ErrorKind::Other),
            },
            ArchiveError::ReplaceFailed(exarch_core::ReplaceFailure::new(
                io::Error::from(io::ErrorKind::Other),
                exarch_core::Restore::NotNeeded,
                None,
            )),
        ]
    }

    #[test]
    fn every_archive_error_has_a_dedicated_context() {
        for err in every_archive_error_variant() {
            assert!(
                dedicated_context(
                    Operation::Extract,
                    &err,
                    Path::new("a.tar"),
                    ConflictAdvice::UseForce
                )
                .is_some(),
                "{err:?} took the wildcard arm"
            );
        }
    }

    fn occupied_text(conflicts: &[PathBuf]) -> String {
        terminal(
            &occupied_message(Path::new(""), conflicts, ConflictAdvice::UseForce)
                .into_context()
                .parts(),
        )
    }

    #[test]
    fn occupied_message_escapes_hostile_paths() {
        let msg = occupied_text(&[PathBuf::from("a\x1b[2J\nforged")]);
        assert!(msg.ends_with("  a\\x1b[2J\\x0aforged"), "{msg:?}");
    }

    #[test]
    fn occupied_message_singular() {
        let msg = occupied_text(&[PathBuf::from("a.txt")]);
        assert!(msg.starts_with("1 destination file already exists"));
        assert!(msg.contains("a.txt"));
        assert!(!msg.contains("more"));
    }

    #[test]
    fn occupied_message_at_cap_lists_all_without_truncation_note() {
        let conflicts: Vec<_> = (0..MAX_LISTED_CONFLICTS)
            .map(|i| PathBuf::from(format!("f{i}.txt")))
            .collect();
        let msg = occupied_text(&conflicts);
        assert!(msg.starts_with("10 destination files already exist"));
        for i in 0..MAX_LISTED_CONFLICTS {
            assert!(msg.contains(&format!("f{i}.txt")));
        }
        assert!(!msg.contains("more") && !msg.contains("first"));
    }

    #[test]
    fn occupied_message_over_cap_shows_the_first_ten_and_summarizes() {
        let conflicts: Vec<_> = (0..25)
            .map(|i| PathBuf::from(format!("f{i:02}.txt")))
            .collect();
        let msg = occupied_text(&conflicts);
        assert!(msg.starts_with("25 destination files already exist"));
        assert!(msg.contains("first 10 shown"));
        for i in 0..10 {
            assert!(msg.contains(&format!("f{i:02}.txt")));
        }
        for i in 10..25 {
            assert!(!msg.contains(&format!("f{i:02}.txt")));
        }
        assert!(msg.contains("... and 15 more"));
    }

    #[test]
    fn occupied_advice_is_the_hint_and_follows_the_write_mode() {
        let context =
            |advice| occupied_message(Path::new(""), &[PathBuf::from("a")], advice).into_context();
        for advice in [ConflictAdvice::UseForce, ConflictAdvice::ForceCannotReplace] {
            let context = context(advice);
            assert!(
                !terminal(&context.parts()).contains("--force"),
                "{advice:?}"
            );
            assert_eq!(context.hint().map(|h| raw(&h)), Some(advice.hint()));
        }
        assert_eq!(
            raw(&context(ConflictAdvice::UseForce).hint().unwrap()),
            "Use --force to overwrite."
        );
        let cannot = ConflictAdvice::ForceCannotReplace.hint();
        assert!(cannot.contains("cannot replace"), "{cannot}");
        assert!(!cannot.contains("Use --force"), "{cannot}");
    }

    #[test]
    fn a_failed_replace_says_what_to_do_with_what_it_left() {
        let hint = |restore, leftover| {
            let failure =
                ReplaceFailure::new(io::Error::from(io::ErrorKind::Other), restore, leftover);
            let context = replace_failed_context(Message::default(), &failure).into_context();
            context.hint().map(|h| raw(&h))
        };
        assert_eq!(hint(Restore::Restored, None), None);
        assert!(
            hint(
                Restore::Failed {
                    backup: PathBuf::from("b"),
                    error: io::Error::from(io::ErrorKind::Other),
                },
                None
            )
            .is_some_and(|h| h.contains("backup path"))
        );
    }

    #[test]
    fn each_fact_is_stated_once() {
        let once = |err: ArchiveError, phrase: &str| {
            let text = full_text(&convert_error(Operation::Extract, err, Path::new("a.tar")));
            assert_eq!(text.to_lowercase().matches(phrase).count(), 1, "{text}");
        };
        once(
            ArchiveError::SourceNotFound {
                path: PathBuf::from("x"),
            },
            "source path not found",
        );
        once(
            ArchiveError::SourceNotAccessible {
                path: PathBuf::from("x"),
                error: io::Error::from(io::ErrorKind::PermissionDenied),
            },
            "source path is not accessible",
        );
        once(
            ArchiveError::ReplaceFailed(ReplaceFailure::new(
                io::Error::other("boom"),
                Restore::Restored,
                None,
            )),
            "failed to replace the destination",
        );
        once(
            ArchiveError::from(Violation::HardlinkTargetNotExtracted {
                link: "l".into(),
                target: "t".into(),
            }),
            "which the selection does not extract",
        );
        once(
            ArchiveError::from(Violation::DestinationChanged),
            "destination changed while it was being replaced",
        );
    }

    #[test]
    fn a_partial_report_is_followed_by_its_cause_on_its_own_line() {
        let cause = convert_error(
            Operation::Extract,
            ArchiveError::from(Violation::SolidArchive),
            Path::new("a.7z"),
        );
        let partial = anyhow::Error::new(PartialExtractionContext {
            report: ExtractionReport::default(),
            writes: PartialWrites::RolledBack,
            leftover: None,
            inner: cause,
        });
        let text = chain_text(&partial);
        assert!(!text.contains(".:"), "{text}");
        let mut lines = text.lines();
        assert!(
            lines
                .next()
                .is_some_and(|report| report.ends_with("left unchanged.")),
            "{text}"
        );
        assert!(
            lines
                .next()
                .is_some_and(|cause| cause.starts_with("Security violation")),
            "{text}"
        );
    }

    fn rolled_back_with_leftover() -> anyhow::Error {
        convert_error(
            Operation::Extract,
            ArchiveError::Cancelled.rolled_back_with(Some(exarch_core::StagingLeftover::new(
                PathBuf::from("out/.exarch-AbC123"),
            ))),
            Path::new("a.tar"),
        )
    }

    #[test]
    fn a_rolled_back_run_names_the_staging_directory_it_left() {
        let error = rolled_back_with_leftover();
        let text = terminal(&cli_message(error.as_ref()).unwrap());
        assert!(text.contains("Nothing was published"), "{text}");
        assert!(text.contains("remains at out/.exarch-AbC123."), "{text}");
        assert_eq!(
            chain_hints(&error, terminal),
            ["Remove the staging directory when you no longer need it."]
        );
        assert_eq!(leftover_path(&error), Some(Path::new("out/.exarch-AbC123")));
    }

    #[test]
    fn a_clean_rollback_names_no_leftover() {
        let error = convert_error(
            Operation::Extract,
            ArchiveError::Cancelled.rolled_back_with(None),
            Path::new("a.tar"),
        );
        assert_eq!(leftover_path(&error), None);
        assert!(chain_hints(&error, terminal).is_empty());
    }

    #[test]
    fn a_failed_replace_and_a_left_reservation_expose_their_path() {
        let replace = convert_error(
            Operation::Extract,
            ArchiveError::ReplaceFailed(ReplaceFailure::new(
                io::Error::from(io::ErrorKind::Other),
                Restore::Restored,
                Some(exarch_core::StagingLeftover::new(PathBuf::from(
                    "p/.exarch-X",
                ))),
            )),
            Path::new("a.tar"),
        );
        assert_eq!(leftover_path(&replace), Some(Path::new("p/.exarch-X")));
        let reservation = convert_error(
            Operation::Create,
            ArchiveError::OutputReservationLeft {
                path: PathBuf::from("o.tar"),
                error: io::Error::from(io::ErrorKind::Other),
            },
            Path::new("o.tar"),
        );
        assert_eq!(leftover_path(&reservation), Some(Path::new("o.tar")));
    }

    fn hint_probes() -> Vec<ArchiveError> {
        vec![
            ArchiveError::from(Violation::LinksNotAllowed(LinkKind::Symlink)),
            ArchiveError::from(Violation::LinksNotAllowed(LinkKind::Hardlink)),
            ArchiveError::from(Violation::SolidArchive),
            ArchiveError::from(Violation::BannedComponent {
                component: ".git".into(),
            }),
            ArchiveError::from(Violation::PathDepth { depth: 2, max: 1 }),
            ArchiveError::OutputExists {
                path: PathBuf::from("o"),
            },
            ArchiveError::QuotaExceeded {
                resource: exarch_core::QuotaResource::FileCount { current: 2, max: 1 },
            },
            ArchiveError::ZipBomb(ZipBombDetails::new(
                ZipBombScope::Entry,
                Compressed(1),
                Uncompressed(1 << 30),
            )),
        ]
    }
}
