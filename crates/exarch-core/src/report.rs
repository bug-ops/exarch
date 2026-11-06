//! Extraction operation reporting.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use crate::ArchiveError;
use crate::Result;
use crate::closed_enum::closed_enum;
use crate::error::QuotaResource;

closed_enum! {
    /// Why an entry was left out of an extraction or creation.
    ///
    /// The string form is stable and shared by every front end (for example as
    /// a `--json` key).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SkipKind;
    ///
    /// assert_eq!(SkipKind::Duplicate.as_str(), "duplicate");
    /// assert!(SkipKind::ALL.contains(&SkipKind::Excluded));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    pub enum SkipKind {
        /// A pre-existing destination entry kept under the skip-duplicates policy
        Duplicate => "duplicate",
        /// A file refused by the extension allowlist
        ExtensionNotAllowed => "extension_not_allowed",
        /// An entry matched by a creation exclude pattern
        Excluded => "excluded",
        /// A hidden entry left out by a creation configuration
        Hidden => "hidden",
        /// A file larger than the creation file size limit
        OverMaxFileSize => "over_max_file_size",
        /// A symlink that cannot be stored (not followed, or unsupported here)
        SymlinkUnsupported => "symlink_unsupported",
        /// An entry that could not be read
        Unreadable => "unreadable",
    }
}

/// One entry left out of an operation, with the reason.
///
/// # Examples
///
/// ```
/// use exarch_core::Skip;
/// use exarch_core::SkipKind;
///
/// let skip = Skip::new(SkipKind::Excluded, "target/debug");
/// assert_eq!(skip.kind, SkipKind::Excluded);
/// assert_eq!(skip.to_string(), "skipped target/debug (excluded)");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Skip {
    /// Why the entry was skipped.
    pub kind: SkipKind,

    /// The entry's path as the operation names it.
    pub path: PathBuf,

    /// The I/O failure behind an [`SkipKind::Unreadable`] skip.
    pub io_kind: Option<io::ErrorKind>,
}

impl Skip {
    /// Builds a skip of `kind` for `path`, with no I/O failure attached.
    #[must_use]
    pub fn new(kind: SkipKind, path: impl Into<PathBuf>) -> Self {
        Self {
            kind,
            path: path.into(),
            io_kind: None,
        }
    }

    /// Attaches the I/O failure that caused the skip.
    #[must_use]
    pub const fn with_io_kind(mut self, io_kind: io::ErrorKind) -> Self {
        self.io_kind = Some(io_kind);
        self
    }
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "skipped {} ({})", self.path.display(), self.kind)?;
        self.io_kind
            .map_or(Ok(()), |io_kind| write!(f, ": {io_kind}"))
    }
}

/// Everything an operation left out: exact counts per [`SkipKind`] plus a
/// bounded sample of the individual entries.
///
/// The counts are exact however many entries are skipped. The sample keeps the
/// first [`Skips::SAMPLE_CAP`] entries, so a report stays small on an archive
/// with millions of skipped entries (#490, #495).
///
/// # Examples
///
/// ```
/// use exarch_core::ExtractionReport;
///
/// let report = ExtractionReport::new();
/// assert_eq!(report.skipped.total(), 0);
/// assert!(report.skipped.sample().is_empty());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skips {
    // Boxed so a report with nothing skipped stays small: the report rides
    // inside `ArchiveError::PartialExtraction`.
    detail: Option<Box<SkipDetail>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SkipDetail {
    counts: BTreeMap<SkipKind, usize>,
    sample: Vec<Skip>,
}

impl Skips {
    /// The most individual skips [`sample`](Self::sample) keeps.
    pub const SAMPLE_CAP: usize = 64;

    /// Returns how many entries were skipped, over all kinds.
    #[must_use]
    pub fn total(&self) -> usize {
        self.detail.as_ref().map_or_default(|detail| {
            detail
                .counts
                .values()
                .fold(0_usize, |sum, count| sum.saturating_add(*count))
        })
    }

    /// Returns how many entries were skipped for `kind`.
    #[must_use]
    pub fn count(&self, kind: SkipKind) -> usize {
        self.detail
            .as_ref()
            .and_then(|detail| detail.counts.get(&kind))
            .copied()
            .unwrap_or(0)
    }

    /// Returns the first [`SAMPLE_CAP`](Self::SAMPLE_CAP) skipped entries, in
    /// the order they were skipped.
    #[must_use]
    pub fn sample(&self) -> &[Skip] {
        self.detail
            .as_ref()
            .map_or(&[], |detail| detail.sample.as_slice())
    }

    /// Returns whether nothing was skipped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detail.is_none()
    }

    /// Counts `skip`, failing closed instead of wrapping when its kind's
    /// counter is at its maximum (#515).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] with
    /// [`QuotaResource::IntegerOverflow`] when the counter would overflow.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Skip;
    /// use exarch_core::SkipKind;
    /// use exarch_core::Skips;
    ///
    /// let mut skips = Skips::default();
    /// skips.record(Skip::new(SkipKind::Excluded, "a.tmp"))?;
    /// assert_eq!(skips.count(SkipKind::Excluded), 1);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn record(&mut self, skip: Skip) -> Result<()> {
        let detail = self.detail.get_or_insert_default();
        let count = detail.counts.entry(skip.kind).or_insert(0);
        *count = count.checked_add(1).ok_or(ArchiveError::QuotaExceeded {
            resource: QuotaResource::IntegerOverflow,
        })?;
        if detail.sample.len() < Self::SAMPLE_CAP {
            detail.sample.push(skip);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_saturated_count(kind: SkipKind) -> Self {
        Self {
            detail: Some(Box::new(SkipDetail {
                counts: BTreeMap::from([(kind, usize::MAX)]),
                sample: Vec::new(),
            })),
        }
    }
}

/// A condition of an extraction worth surfacing that is not a skipped entry.
///
/// # Examples
///
/// ```
/// use exarch_core::ExtractionWarning;
///
/// let warning = ExtractionWarning::AntiItemsSkipped { count: 1 };
/// assert_eq!(
///     warning.to_string(),
///     "skipped 1 7z anti-item (deletion markers are not applied)"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractionWarning {
    /// 7z anti-items, which mark deletions in an update archive, were not
    /// applied.
    AntiItemsSkipped {
        /// How many anti-items the archive holds.
        count: u64,
    },

    /// The backup of the original destination, kept for an atomic
    /// replacement, could not be removed and must be cleaned up manually.
    BackupCleanupFailed {
        /// Where the backup remains.
        path: PathBuf,
        /// Whether the backup's identity could not be verified before removal.
        identity_unverified: bool,
        /// Why the removal failed.
        error: String,
    },
}

impl fmt::Display for ExtractionWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackupCleanupFailed {
                path,
                identity_unverified,
                error,
            } => {
                let qualifier = if *identity_unverified {
                    " (its identity could not be verified on this platform)"
                } else {
                    ""
                };
                write!(
                    f,
                    "failed to remove backup of the original destination at {}{qualifier} \
                     ({error}); it must be cleaned up manually",
                    path.display()
                )
            }
            Self::AntiItemsSkipped { count } => {
                let noun = if *count == 1 {
                    "anti-item"
                } else {
                    "anti-items"
                };
                write!(
                    f,
                    "skipped {count} 7z {noun} (deletion markers are not applied)"
                )
            }
        }
    }
}

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: usize,

    /// Number of directories created.
    pub directories_created: usize,

    /// Number of symlinks created.
    pub symlinks_created: usize,

    /// Total bytes written to disk.
    pub bytes_written: u64,

    /// Duration of the extraction operation.
    pub duration: Duration,

    /// Entries left out of the extraction, by reason.
    pub skipped: Skips,

    /// Conditions worth surfacing that are not skipped entries.
    pub warnings: Vec<ExtractionWarning>,
}

impl ExtractionReport {
    /// Creates a new empty extraction report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a warning to the report.
    pub fn add_warning(&mut self, warning: ExtractionWarning) {
        self.warnings.push(warning);
    }

    /// Returns how many entries were skipped, over all reasons.
    #[must_use]
    pub fn files_skipped(&self) -> usize {
        self.skipped.total()
    }

    /// Returns the total number of items actually written to disk
    /// (`files_extracted + directories_created + symlinks_created`).
    ///
    /// This deliberately excludes [`files_skipped`](Self::files_skipped): a
    /// report can carry meaningful progress — skipped entries, warnings —
    /// while this is `0`. Callers deciding whether a report is worth
    /// surfacing (e.g. `ArchiveError::partial_or`) must check
    /// `files_skipped`/[`has_warnings`](Self::has_warnings) too, not rely on
    /// this alone.
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.files_extracted + self.directories_created + self.symlinks_created
    }

    /// Returns whether any warnings were generated.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// How many entries an operation has, when it knows.
///
/// A stream such as a TAR archive cannot count its entries before reading
/// them, so it reports [`Unknown`](Self::Unknown) rather than a count a
/// callback might divide by.
///
/// # Examples
///
/// ```
/// use exarch_core::EntryTotal;
///
/// let total = EntryTotal::Known(3);
/// assert_eq!(total.known(), Some(3));
/// assert_eq!(EntryTotal::Unknown.known(), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryTotal {
    /// The operation holds exactly this many entries.
    Known(usize),

    /// The entry count is not known until the operation ends.
    Unknown,
}

impl EntryTotal {
    /// Returns the count when it is known.
    #[must_use]
    pub const fn known(self) -> Option<usize> {
        match self {
            Self::Known(total) => Some(total),
            Self::Unknown => None,
        }
    }
}

/// Where an entry sits in the operation: its 1-based number and the total.
///
/// # Examples
///
/// ```
/// use exarch_core::EntryPosition;
/// use exarch_core::EntryTotal;
///
/// let position = EntryPosition::at_index(0, EntryTotal::Known(4));
/// assert_eq!(position.current.get(), 1);
/// assert_eq!(position.total, EntryTotal::Known(4));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryPosition {
    /// The entry's number, counting from 1.
    pub current: NonZeroUsize,

    /// How many entries the operation holds, when known.
    pub total: EntryTotal,
}

impl EntryPosition {
    /// Builds a position from its parts.
    #[must_use]
    pub const fn new(current: NonZeroUsize, total: EntryTotal) -> Self {
        Self { current, total }
    }

    /// Builds the position of the entry at the 0-based `index`.
    #[must_use]
    pub const fn at_index(index: usize, total: EntryTotal) -> Self {
        Self::new(NonZeroUsize::MIN.saturating_add(index), total)
    }
}

/// Callback trait for progress reporting during archive operations.
///
/// Implement this trait to receive progress updates during extraction or
/// creation. The trait requires `Send` to allow use in multi-threaded contexts.
///
/// # Examples
///
/// ```
/// use exarch_core::EntryPosition;
/// use exarch_core::EntryTotal;
/// use exarch_core::ProgressCallback;
/// use std::path::Path;
///
/// struct SimpleProgress;
///
/// impl ProgressCallback for SimpleProgress {
///     fn on_entry_start(&mut self, path: &Path, position: EntryPosition) {
///         match position.total {
///             EntryTotal::Known(total) => {
///                 println!(
///                     "Processing {}/{}: {}",
///                     position.current,
///                     total,
///                     path.display()
///                 );
///             }
///             _ => println!("Processing {}: {}", position.current, path.display()),
///         }
///     }
///
///     fn on_bytes_written(&mut self, bytes: u64) {
///         // Track bytes written
///     }
///
///     fn on_entry_complete(&mut self, path: &Path) {
///         println!("Completed: {}", path.display());
///     }
///
///     fn on_complete(&mut self) {
///         println!("Operation complete");
///     }
/// }
/// ```
pub trait ProgressCallback: Send {
    /// Called when starting to process an entry.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the entry being processed
    /// * `position` - The entry's 1-based number and the entry total, which is
    ///   [`EntryTotal::Unknown`] for a stream
    fn on_entry_start(&mut self, path: &Path, position: EntryPosition);

    /// Called when bytes are written during extraction or read during creation.
    ///
    /// Granularity is per-entry: called once after the full entry is written.
    /// Partial writes on failure are not reported. Not called for entries that
    /// produce no output (directories, skipped entries).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes written/read in this update
    fn on_bytes_written(&mut self, bytes: u64);

    /// Called when an entry has been completely processed.
    ///
    /// Always called after [`on_entry_start`](Self::on_entry_start) for the
    /// same entry, including when extraction of that entry fails. Callers can
    /// rely on this pairing for cleanup or progress accounting.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the entry that was completed
    fn on_entry_complete(&mut self, path: &Path);

    /// Called when the entire operation completes successfully.
    ///
    /// Not called if the operation fails or results in a partial extraction.
    /// Implementors must not rely on this method for cleanup — use `Drop`
    /// instead.
    fn on_complete(&mut self);

    /// Whether the operation should stop, polled by archive creation between
    /// entries and once more before the archive is published.
    ///
    /// The callbacks above cannot fail, so a callback that hit an error of its
    /// own (a raising script callback, a closed channel) reports it here:
    /// creation then stops with an [`ArchiveError::Io`] of kind
    /// [`Interrupted`](std::io::ErrorKind::Interrupted), the staged output is
    /// discarded and a previous archive at the output path stays untouched.
    /// The default never cancels.
    fn is_cancelled(&mut self) -> bool {
        false
    }
}

/// No-op implementation of `ProgressCallback` that does nothing.
///
/// Use this when you don't need progress reporting but the API requires
/// a callback implementation.
#[derive(Debug, Default)]
pub struct NoopProgress;

impl ProgressCallback for NoopProgress {
    fn on_entry_start(&mut self, _path: &Path, _position: EntryPosition) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_new_report() {
        let report = ExtractionReport::new();
        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
        assert_eq!(report.bytes_written, 0);
        assert!(!report.has_warnings());
        assert_eq!(report.files_skipped(), 0);
    }

    #[test]
    fn test_add_warning() {
        let mut report = ExtractionReport::new();
        report.add_warning(ExtractionWarning::AntiItemsSkipped { count: 2 });
        assert!(report.has_warnings());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn test_total_items() {
        let mut report = ExtractionReport::new();
        report.files_extracted = 10;
        report.directories_created = 5;
        report.symlinks_created = 2;
        assert_eq!(report.total_items(), 17);
    }

    #[test]
    fn skips_count_per_kind_and_bound_the_sample() {
        let mut skips = Skips::default();
        for i in 0..Skips::SAMPLE_CAP + 10 {
            skips
                .record(Skip::new(SkipKind::Duplicate, format!("f{i}")))
                .unwrap();
        }
        skips
            .record(Skip::new(SkipKind::Excluded, "x").with_io_kind(io::ErrorKind::NotFound))
            .unwrap();
        assert_eq!(skips.count(SkipKind::Duplicate), Skips::SAMPLE_CAP + 10);
        assert_eq!(skips.count(SkipKind::Excluded), 1);
        assert_eq!(skips.count(SkipKind::Hidden), 0);
        assert_eq!(skips.total(), Skips::SAMPLE_CAP + 11);
        assert_eq!(skips.sample().len(), Skips::SAMPLE_CAP);
        assert!(!skips.is_empty());
    }

    #[test]
    fn skips_fail_closed_at_a_saturated_counter() {
        let mut skips = Skips::with_saturated_count(SkipKind::Duplicate);
        let err = skips
            .record(Skip::new(SkipKind::Duplicate, "a"))
            .unwrap_err();
        assert_matches!(
            err,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        );
        assert_eq!(skips.count(SkipKind::Duplicate), usize::MAX);
        assert!(skips.sample().is_empty());
    }

    #[test]
    fn every_skip_kind_has_a_distinct_string_form() {
        let mut seen: Vec<&str> = SkipKind::ALL.iter().map(|kind| kind.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), SkipKind::ALL.len());
    }

    #[test]
    fn entry_position_numbers_from_one() {
        let position = EntryPosition::at_index(usize::MAX, EntryTotal::Unknown);
        assert_eq!(position.current.get(), usize::MAX);
        assert_eq!(
            EntryPosition::at_index(0, EntryTotal::Unknown)
                .current
                .get(),
            1
        );
    }
}
