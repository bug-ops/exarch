//! Error conversion utilities for CLI.
//!
//! Converts exarch-core's typed errors (thiserror) into user-friendly
//! contextual errors (anyhow) with actionable guidance.
//!
//! CLI-authored messages are structured ([`Part`]) rather than preformatted
//! strings: escaping is a property of the output medium, so the human
//! formatter escapes archive-derived parts for the terminal while `--json`
//! keeps them exact.

use crate::operation::Flag;
use crate::operation::Operation;
use crate::output::terminal::TerminalEntry;
use crate::output::terminal::TerminalPath;
use crate::output::terminal::TerminalText;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ArchiveType;
use exarch_core::CompressionRatio;
use exarch_core::ExtractionReport;
use exarch_core::PartialWrites;
use exarch_core::PathComponentName;
use exarch_core::PolicySetting;
use exarch_core::QuotaKind;
use exarch_core::SecurityConfig;
use exarch_core::SkipKind;
use exarch_core::TarTrailerRefusal;
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
    fn parts(&self) -> Cow<'_, [Part]>;
}

/// The structured message of `link` when it is one of the CLI's own error
/// objects.
pub fn cli_message<'a>(link: &'a (dyn std::error::Error + 'static)) -> Option<Cow<'a, [Part]>> {
    link.downcast_ref::<CliContext>()
        .map(CliMessage::parts)
        .or_else(|| {
            link.downcast_ref::<PartialExtractionContext>()
                .map(CliMessage::parts)
        })
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

/// Builder for the parts of one message.
#[derive(Debug, Default)]
pub struct Message(Vec<Part>);

impl Message {
    /// Appends text written in the source, which may span lines.
    pub fn lit(mut self, text: &'static str) -> Self {
        self.0.push(Part::Lit(text));
        self
    }

    /// Appends a host path (an archive, a destination), escaped for a terminal
    /// and exact in `--json`.
    pub fn path(mut self, path: &Path) -> Self {
        self.0.push(Part::Path(path.to_path_buf()));
        self
    }

    /// Appends the name of an archive entry, rendered injectively.
    pub fn entry(mut self, path: &Path) -> Self {
        self.0.push(Part::Entry(path.to_path_buf()));
        self
    }

    /// Appends single-line text that may derive from an archive, escaped for a
    /// terminal and exact in `--json`.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.0.push(Part::Text(text.into()));
        self
    }

    /// Appends a `HINT:` line when there is advice to give.
    pub fn hint(self, hint: Option<String>) -> Self {
        match hint {
            Some(body) => self.lit("\nHINT: ").text(body),
            None => self,
        }
    }

    /// The finished list of parts.
    pub fn into_parts(self) -> Vec<Part> {
        self.0
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
        ZipBombScope::SolidBlock => {
            Some("Solid 7z blocks use a fixed 1000x limit that the CLI cannot change.".to_owned())
        }
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
/// terminal. `Display` is the message rendered exactly; the wrapped error is
/// exposed as the `source`, so `{:#}` renders `message: error`.
#[derive(Debug)]
pub struct CliContext {
    parts: Vec<Part>,
    source: Option<ArchiveError>,
}

impl CliContext {
    /// A message that wraps no underlying error.
    pub const fn new(message: Vec<Part>) -> Self {
        Self {
            parts: message,
            source: None,
        }
    }

    const fn wrapping(message: Vec<Part>, source: ArchiveError) -> Self {
        Self {
            parts: message,
            source: Some(source),
        }
    }
}

impl CliMessage for CliContext {
    fn parts(&self) -> Cow<'_, [Part]> {
        Cow::Borrowed(&self.parts)
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
    inner: anyhow::Error,
}

impl PartialExtractionContext {
    /// The text for each [`PartialWrites`] state; `None` for a state added to
    /// the `#[non_exhaustive]` enum after this match was written, which
    /// `every_partial_writes_state_has_dedicated_text` rejects.
    fn dedicated_parts(&self) -> Option<Vec<Part>> {
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
                    for &kind in SkipKind::ALL {
                        let count = r.skipped.count(kind);
                        if count > 0 {
                            message = message.lit("\n    ").text(format!("{kind}: {count}"));
                        }
                    }
                }
                if !r.warnings.is_empty() {
                    message = message.lit("\nWarnings:");
                    for warning in &r.warnings {
                        message = message.lit("\n  - ").text(warning.to_string());
                    }
                }
                message.lit("\nHINT: Inspect or remove the output directory before re-running.")
            }
            // The counts and warnings describe the discarded run, not the
            // destination.
            PartialWrites::RolledBack => Message::default().lit(
                "WARNING: Extraction was stopped. The partial extraction was discarded; the \
                 destination was left unchanged.",
            ),
            PartialWrites::Discarded => {
                Message::default().lit("WARNING: Extraction was stopped. Nothing was written.")
            }
            _ => return None,
        };
        Some(message.into_parts())
    }
}

impl CliMessage for PartialExtractionContext {
    fn parts(&self) -> Cow<'_, [Part]> {
        Cow::Owned(self.dedicated_parts().unwrap_or_else(|| {
            Message::default()
                .lit("WARNING: Extraction was stopped.")
                .into_parts()
        }))
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
                 allowed limit. No CLI flag relaxes this. Rust API only: \
                 SecurityConfig::with_max_decoder_memory.",
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
            let (cause, report, writes) = partial.into_parts();
            return anyhow::Error::new(PartialExtractionContext {
                report,
                writes,
                inner: convert_error(op, cause, archive),
            });
        }
        other => other,
    };

    let context = context_message(op, &err, archive);
    anyhow::Error::new(CliContext::wrapping(context.into_parts(), err))
}

fn context_message(op: Operation, err: &ArchiveError, archive: &Path) -> Message {
    let message = Message::default();
    match err {
        ArchiveError::PathTraversal { .. } => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit(
                "' attempted path traversal\n\
                 HINT: This archive may be malicious. Do not extract from untrusted sources.",
            ),
        ArchiveError::ZipBomb(details) => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit("' appears to be a zip bomb")
            .hint(zip_bomb_hint(op, details)),
        ArchiveError::ZipInconsistency(_) => {
            let relax = op.accepts(Flag::ZipConsistency).then(|| {
                format!(
                    " Use {} ignore only for archives from a trusted producer.",
                    Flag::ZipConsistency.long()
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
        ArchiveError::QuotaExceeded { resource } => {
            quota_exceeded_context(op, resource.kind(), archive)
        }
        ArchiveError::SymlinkEscape { .. } | ArchiveError::HardlinkEscape { .. } => message
            .lit("Security violation: Archive '")
            .path(archive)
            .lit(
                "' has a link that escapes the destination\n\
                 HINT: a link resolves outside the destination (an archive link or an existing \
                 destination symlink); no flag relaxes this check.",
            ),
        ArchiveError::Io(_) => message.lit("Failed to process '").path(archive).lit("'"),
        ArchiveError::UnknownFormat { .. } => message
            .lit("Cannot determine archive format")
            .hint(Some(format!("Supported formats: {}", supported_formats()))),
        ArchiveError::SecurityViolation { .. }
        | ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { .. }) => message
            .lit("Security violation while processing '")
            .path(archive)
            .lit("'")
            .hint(Some(relaxation_hint(op, err.relaxable_by()))),
        ArchiveError::InvalidArchive(_)
        | ArchiveError::TarAmbiguity(_)
        | ArchiveError::TarTrailer(_) => message
            .lit("Invalid archive '")
            .path(archive)
            .lit("'\nHINT: The archive may be corrupted or malformed."),
        ArchiveError::InvalidConfiguration { setting, problem } => message
            .lit("Invalid configuration: ")
            .text(setting.describe(problem))
            .lit("\nHINT: Check the flags you passed and their allowed value ranges."),
        ArchiveError::SourceNotFound { .. } => message.lit("Source path not found").lit(match op {
            Operation::Create => "\nHINT: Verify the source path exists and is readable.",
            Operation::Extract | Operation::List | Operation::Verify => {
                "\nHINT: Verify the archive path exists and is readable."
            }
        }),
        ArchiveError::SourceNotAccessible { error, .. } => message
            .lit("Source path is not accessible")
            .lit(if error.kind() == io::ErrorKind::PermissionDenied {
                match op {
                    Operation::Create => "\nHINT: Check file permissions on the source.",
                    Operation::Extract | Operation::List | Operation::Verify => {
                        "\nHINT: Check file permissions on the archive."
                    }
                }
            } else {
                ""
            }),
        ArchiveError::OutputExists { .. } => message.lit("Output path already exists").hint(
            op.accepts(Flag::Force)
                .then(|| format!("Use {} to overwrite.", Flag::Force.long())),
        ),
        ArchiveError::InvalidPermissions { mode, .. } => message.text(format!(
            "Invalid permissions {:#o}: blocked by security policy.",
            mode.get()
        )),
        ArchiveError::InvalidCompressionLevel { level } => message.text(format!(
            "Invalid compression level {level}: must be between 1 and 9."
        )),

        ArchiveError::Cancelled => message.lit("Operation cancelled"),
        ArchiveError::DestinationOccupied { .. } => message
            .lit("The destination already holds files the archive would write")
            .hint(
                op.accepts(Flag::Force)
                    .then(|| format!("Use {} to overwrite.", Flag::Force.long())),
            ),
        ArchiveError::OutputReservationLeft { .. } => {
            message.lit("An empty reservation file was left at the output path")
        }
        ArchiveError::ReplaceFailed(_) => message.lit("Failed to replace the destination"),

        // Forward-compat: a variant added to ArchiveError after this match was
        // written. #[non_exhaustive] requires this arm to compile against a
        // newer exarch-core; there is no more specific context to add.
        _ => message
            .lit("Error while processing '")
            .path(archive)
            .lit("'"),
    }
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
mod tests {
    use super::*;
    use exarch_core::Compressed;
    use exarch_core::LinkKind;
    use exarch_core::Uncompressed;
    use exarch_core::Violation;
    use std::io;
    use std::path::PathBuf;

    fn source_not_accessible_message(kind: io::ErrorKind) -> String {
        let err = ArchiveError::SourceNotAccessible {
            path: PathBuf::from("src/a.txt"),
            error: io::Error::from(kind),
        };
        format!(
            "{:?}",
            convert_error(Operation::Create, err, Path::new("o.tar"))
        )
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
        let msg = format!("{converted:?}");
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
        format!("{converted:?}")
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
            let msg = format!("{converted:#}");
            assert!(msg.contains("no flag relaxes this check"), "{msg}");
            assert!(!msg.contains("--allow-"), "{msg}");
        }
    }

    #[test]
    fn test_hardlink_escape_path_appears_once() {
        let path = PathBuf::from("hard/link/escape");
        let err = ArchiveError::HardlinkEscape { path };
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:?}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
        assert!(msg.contains('0'), "level missing: {msg}");
        assert!(msg.contains("between 1 and 9"), "range hint missing: {msg}");
    }

    #[test]
    fn test_security_violation_reason_appears_exactly_once() {
        let err = ArchiveError::from(Violation::EncryptedEntry {
            name: "distinctive-entry".into(),
        });
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        format!("{converted:#}")
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
                |m| raw(&m.into_parts()),
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
        let msg = format!("{converted:#}");
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
            .into_parts();
        assert_eq!(raw(&message), "a\nb p\x1b t\x1b");
        assert_eq!(terminal(&message), "a\nb p\\x1b t\\x1b");
    }

    #[test]
    fn every_partial_writes_state_has_dedicated_text() {
        for &writes in PartialWrites::ALL {
            let context = PartialExtractionContext {
                report: ExtractionReport::default(),
                writes,
                inner: anyhow::anyhow!("inner"),
            };
            assert!(
                context.dedicated_parts().is_some(),
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
                    .map(|c| raw(&c.parts()))
                    .unwrap_or_default();
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
