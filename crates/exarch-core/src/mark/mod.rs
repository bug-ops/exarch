//! Download-origin mark propagation (Mark-of-the-Web on Windows, the
//! quarantine attribute on macOS).
//!
//! An archive downloaded from the internet carries a mark that the OS reads
//! per file; extraction that drops it launders the content. With
//! [`MarkPropagation::WhenMarked`] the mark of the archive file is read once,
//! through the archive's own open handle, and written to every file the run
//! creates, through the handle that created it. The mark never comes from
//! archive content. A Windows host refuses entry names with `:` (alternate
//! data streams), so an archive cannot name a stream; other hosts treat `:` as
//! a regular character, and such an entry is an ordinary file.
//!
//! The mark is the last write to a file, before its final restrictive mode is
//! applied (see `PendingMode`) and before the file is renamed into place.
//! Linux has no mark, so the policy is a reported no-op there.

use std::cell::Cell;
use std::fs::File;
use std::rc::Rc;

use crate::ArchiveError;
use crate::ExtractionReport;
use crate::Result;
use crate::closed_enum::closed_enum;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(any(target_os = "macos", test))]
mod quarantine;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(any(windows, test))]
mod zone;

#[cfg(not(any(target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "macos", windows)))]
use unsupported as platform;

closed_enum! {
    /// Whether extraction copies the archive file's download-origin mark onto
    /// the files it creates.
    ///
    /// The mark is the Windows `Zone.Identifier` stream (Mark-of-the-Web) or
    /// the macOS `com.apple.quarantine` attribute. `SmartScreen`, Office
    /// Protected View and Gatekeeper decide whether to warn from that mark on
    /// each file, so an extractor that drops it removes the warning.
    ///
    /// Only the mark of the archive file itself is ever propagated, read
    /// through the handle the archive is extracted from. Marks, attributes or
    /// streams stored inside an archive are never restored. Linux has no
    /// standard mark and extracted files are never marked there.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::MarkPropagation;
    ///
    /// assert_eq!(MarkPropagation::default(), MarkPropagation::Never);
    /// assert_eq!(MarkPropagation::WhenMarked.as_str(), "when_marked");
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum MarkPropagation {
        /// Do not read the archive's mark and do not mark any file.
        #[default]
        Never => "never",

        /// Mark every extracted file when the archive file bears a mark and
        /// the platform defines one; on macOS also every directory the run
        /// creates. A failed write is counted in the `failed` field of
        /// [`MarkOutcome::Propagated`] and extraction continues.
        WhenMarked => "when_marked",
    }
}

/// What mark propagation did during one extraction.
///
/// Carried by [`ExtractionReport::mark`]. Counts cover the objects the run
/// marked: every extracted file (a hardlink entry is its own file) and, on
/// macOS, every directory the run created. Entries that were skipped, symlinks
/// and pre-existing directories are never counted.
///
/// # Examples
///
/// ```
/// use exarch_core::ExtractionReport;
/// use exarch_core::MarkOutcome;
///
/// assert_eq!(ExtractionReport::new().mark, MarkOutcome::NotRequested);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MarkOutcome {
    /// The policy was [`MarkPropagation::Never`].
    #[default]
    NotRequested,

    /// The platform defines no mark (Linux and other Unix), so nothing was
    /// read or written.
    UnsupportedPlatform,

    /// The archive file bears no mark, so no file was marked.
    Unmarked,

    /// The archive file's mark could not be read because of an I/O error, so
    /// no file was marked. A mark that is present but malformed or oversized is
    /// not this: it is propagated as the most conservative mark.
    Unreadable,

    /// The archive file is marked and the mark was written where possible.
    Propagated {
        /// Objects that now carry the mark.
        marked: usize,
        /// Objects whose mark could not be written; extraction went on.
        failed: usize,
    },
}

impl MarkOutcome {
    /// The stable name of this state, shared by every front end.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::MarkOutcome;
    ///
    /// assert_eq!(MarkOutcome::Unmarked.as_str(), "unmarked");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Unmarked => "unmarked",
            Self::Unreadable => "unreadable",
            Self::Propagated { .. } => "propagated",
        }
    }

    /// How many objects were marked; zero unless the state is
    /// [`Propagated`](Self::Propagated).
    #[must_use]
    pub const fn marked(&self) -> usize {
        match self {
            Self::Propagated { marked, .. } => *marked,
            _ => 0,
        }
    }

    /// How many objects could not be marked; zero unless the state is
    /// [`Propagated`](Self::Propagated).
    #[must_use]
    pub const fn failed(&self) -> usize {
        match self {
            Self::Propagated { failed, .. } => *failed,
            _ => 0,
        }
    }

    /// Whether any object the run created is missing the mark it should
    /// carry.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::MarkOutcome;
    ///
    /// assert!(!MarkOutcome::Unmarked.has_failures());
    /// assert!(
    ///     MarkOutcome::Propagated {
    ///         marked: 1,
    ///         failed: 1
    ///     }
    ///     .has_failures()
    /// );
    /// ```
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        matches!(self, Self::Propagated { failed, .. } if *failed > 0)
    }
}

/// The archive file's mark as the platform reads it.
#[derive(Clone, Copy)]
enum SourceState {
    Marked(platform::Mark),
    Unmarked,
    Unreadable,
    UnsupportedPlatform,
}

/// The mark of one archive file and the counts of what the run marked with it.
///
/// Exists only under [`MarkPropagation::WhenMarked`]; under `Never` no value
/// is built, so no read and no deferred create can happen.
pub(crate) struct MarkRun {
    state: SourceState,
    marked: Cell<usize>,
    failed: Cell<usize>,
}

impl std::fmt::Debug for MarkRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkRun")
            .field("outcome", &self.outcome())
            .finish()
    }
}

impl MarkRun {
    /// Reads the mark of `source` when `policy` asks for propagation.
    ///
    /// `None` under [`MarkPropagation::Never`], without touching `source`.
    pub(crate) fn open(policy: MarkPropagation, source: &File) -> Option<Rc<Self>> {
        match policy {
            MarkPropagation::Never => None,
            MarkPropagation::WhenMarked => Some(Rc::new(Self::read(source))),
        }
    }

    fn read(source: &File) -> Self {
        if !platform::SUPPORTED {
            return Self::of(SourceState::UnsupportedPlatform);
        }
        Self::of(match platform::read(source) {
            Ok(Some(mark)) => SourceState::Marked(mark),
            Ok(None) => SourceState::Unmarked,
            Err(_) => SourceState::Unreadable,
        })
    }

    const fn of(state: SourceState) -> Self {
        Self {
            state,
            marked: Cell::new(0),
            failed: Cell::new(0),
        }
    }

    /// Whether this run writes marks.
    pub(crate) const fn is_marking(&self) -> bool {
        matches!(self.state, SourceState::Marked(_))
    }

    /// Writes the mark through `file`, the handle that created it, and counts
    /// the result; a failure never aborts the extraction.
    pub(crate) fn mark_file(&self, file: &File) {
        if let SourceState::Marked(mark) = self.state {
            self.count(platform::write_file(mark, file).is_ok());
        }
    }

    /// Writes the mark through `dir`, a directory this run created.
    #[cfg(target_os = "macos")]
    pub(crate) fn mark_dir(&self, dir: &impl std::os::fd::AsFd) {
        if let SourceState::Marked(mark) = self.state {
            self.count(platform::write_dir(mark, dir).is_ok());
        }
    }

    fn count(&self, written: bool) {
        if written {
            self.marked.set(self.marked.get().saturating_add(1));
        } else {
            self.failed.set(self.failed.get().saturating_add(1));
        }
    }

    fn outcome(&self) -> MarkOutcome {
        match self.state {
            SourceState::Marked(_) => MarkOutcome::Propagated {
                marked: self.marked.get(),
                failed: self.failed.get(),
            },
            SourceState::Unmarked => MarkOutcome::Unmarked,
            SourceState::Unreadable => MarkOutcome::Unreadable,
            SourceState::UnsupportedPlatform => MarkOutcome::UnsupportedPlatform,
        }
    }

    /// Records what `run` did in the report `result` carries, a partial report
    /// included; `None` leaves `result` as it is.
    pub(crate) fn stamp(
        run: Option<&Self>,
        result: Result<ExtractionReport>,
    ) -> Result<ExtractionReport> {
        let Some(run) = run else {
            return result;
        };
        match result {
            Ok(mut report) => {
                report.mark = run.outcome();
                Ok(report)
            }
            Err(ArchiveError::PartialExtraction(partial)) => {
                let (cause, mut report, writes) = partial.into_parts();
                report.mark = run.outcome();
                Err(ArchiveError::PartialExtraction(crate::Partial::new(
                    cause, report, writes,
                )))
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn never_builds_no_run_and_reads_nothing() {
        let file = tempfile::tempfile().unwrap();
        assert!(MarkRun::open(MarkPropagation::Never, &file).is_none());
    }

    #[test]
    fn an_unmarked_file_reads_as_unmarked_or_unsupported() {
        let file = tempfile::tempfile().unwrap();
        let run = MarkRun::open(MarkPropagation::WhenMarked, &file).unwrap();
        let expected = if platform::SUPPORTED {
            MarkOutcome::Unmarked
        } else {
            MarkOutcome::UnsupportedPlatform
        };
        assert_eq!(run.outcome(), expected);
    }

    #[test]
    fn stamp_records_the_outcome_in_a_partial_report() {
        let run = MarkRun::of(SourceState::Unmarked);
        let mut report = ExtractionReport::new();
        report.files_extracted = 1;
        let partial = ArchiveError::partial_or(report, ArchiveError::Cancelled);
        let stamped = MarkRun::stamp(Some(&run), Err(partial)).unwrap_err();
        let ArchiveError::PartialExtraction(partial) = stamped else {
            panic!("a partial extraction stays partial");
        };
        assert_eq!(partial.report().mark, MarkOutcome::Unmarked);
        assert_eq!(partial.report().files_extracted, 1);
    }

    #[test]
    fn stamp_without_a_run_leaves_the_report_untouched() {
        let report = MarkRun::stamp(None, Ok(ExtractionReport::new())).unwrap();
        assert_eq!(report.mark, MarkOutcome::NotRequested);
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn marked_run() -> MarkRun {
            let source = tempfile::tempfile().unwrap();
            rustix::fs::fsetxattr(
                &source,
                "com.apple.quarantine",
                b"0083;5f3c8d11;Safari;3F2D5A10-1111-4222-8333-444455556666",
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            MarkRun::read(&source)
        }

        #[test]
        fn a_failed_write_is_counted_and_never_an_error() {
            let run = marked_run();
            assert!(run.is_marking());
            let file = tempfile::tempfile().unwrap();
            file.set_permissions(std::fs::Permissions::from_mode(0o444))
                .unwrap();
            run.mark_file(&file);
            assert_eq!(
                run.outcome(),
                MarkOutcome::Propagated {
                    marked: 0,
                    failed: 1
                }
            );
            assert!(run.outcome().has_failures());
        }

        #[test]
        fn a_write_before_the_mode_succeeds_and_is_counted() {
            let run = marked_run();
            let file = tempfile::tempfile().unwrap();
            run.mark_file(&file);
            assert_eq!(
                run.outcome(),
                MarkOutcome::Propagated {
                    marked: 1,
                    failed: 0
                }
            );
        }
    }
}
