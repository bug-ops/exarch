//! Payload integrity pass for `verify`.
//!
//! The pass runs inside the listing loops, so every outcome is recorded in the
//! same iteration that adds the manifest entry and entry/outcome alignment
//! holds by construction. Admission uses the strict validated config (its own
//! quota tracker and ratio check, which mirror `verify_manifest`) and a
//! [`DecompressionBudget`] for the extra decoding listing does not already do.
//!
//! Status is derived from the issues the pass produces: a checksum or decoder
//! failure is a High `CorruptData` issue; anything that could not be verified
//! is counted per [`UnverifiedReason`] and reported as one archive-level
//! Medium `IntegrityIncomplete` issue.

use std::fmt;
use std::io;
use std::io::Read;
use std::path::Path;

use crate::ArchiveError;
use crate::DecompressionBudget;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::CopyError;
use crate::copy::copy_bounded;
use crate::copy::declared_size_exceeded;
use crate::formats::tar_metadata_limit::budget_violation;
use crate::formats::zip::ZIP_DECLARED_SIZE_EXCEEDED;
use crate::formats::zip::ZIP_INVALID_CHECKSUM;
use crate::inspection::manifest::EntryCompression;
use crate::inspection::report::IntegrityGaps;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;
use crate::security::quota::QuotaTracker;
use crate::security::zipbomb::validate_entry_compression;

/// A typed decoding failure; the one table in
/// [`IntegrityPass::record`] maps it to an issue.
#[derive(Debug)]
pub enum DecodeFailure {
    Checksum,
    Malformed(io::Error),
    Truncated {
        declared: u64,
        actual: Option<u64>,
    },
    DeclaredSizeOverrun {
        declared: u64,
    },
    ResourceLimit(ArchiveError),
    /// An unsupported method, encrypted content or unparseable coder setup.
    NotDecodable(ArchiveError),
    Io(io::Error),
}

impl fmt::Display for DecodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checksum => f.write_str("checksum mismatch"),
            Self::Malformed(e) => write!(f, "decoder error: {e}"),
            Self::Truncated {
                declared,
                actual: Some(actual),
            } => write!(f, "truncated: read {actual} of {declared} bytes"),
            Self::Truncated {
                declared,
                actual: None,
            } => write!(f, "truncated: stream ended before {declared} bytes"),
            Self::DeclaredSizeOverrun { declared } => {
                write!(f, "data exceeds the declared size of {declared} bytes")
            }
            Self::ResourceLimit(e) | Self::NotDecodable(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl DecodeFailure {
    /// Classifies a copy failure for an entry of `declared` bytes.
    pub fn from_copy(err: CopyError, declared: u64) -> Self {
        match err {
            CopyError::Read(e) => Self::from_read_error(e, declared),
            CopyError::Write(e) => Self::Io(e),
            CopyError::Overrun { declared } => Self::DeclaredSizeOverrun { declared },
            CopyError::Short { declared, actual } => Self::Truncated {
                declared,
                actual: Some(actual),
            },
            CopyError::Overflow => Self::ResourceLimit(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            }),
        }
    }

    /// Classifies a failure of the 7z block decoder (setting up or running it).
    pub fn from_sevenz(err: sevenz_rust2::Error) -> Self {
        use sevenz_rust2::Error;
        match err {
            Error::ChecksumVerificationFailed => Self::Checksum,
            Error::Io(e, _) => Self::from_read_error(e, 0),
            Error::Other(reason) => Self::Malformed(io::Error::other(reason.into_owned())),
            other => Self::NotDecodable(ArchiveError::from(other)),
        }
    }

    fn from_read_error(e: io::Error, declared: u64) -> Self {
        if let Some(limit) = budget_violation(&e) {
            return Self::ResourceLimit(limit);
        }
        let message = e.to_string();
        if e.kind() == io::ErrorKind::InvalidData && message == ZIP_INVALID_CHECKSUM {
            return Self::Checksum;
        }
        if e.kind() == io::ErrorKind::InvalidData && message == ZIP_DECLARED_SIZE_EXCEEDED {
            return Self::DeclaredSizeOverrun { declared };
        }
        if e.get_ref()
            .and_then(|inner| inner.downcast_ref::<sevenz_rust2::Error>())
            .is_some_and(|inner| matches!(inner, sevenz_rust2::Error::ChecksumVerificationFailed))
        {
            return Self::Checksum;
        }
        if e.raw_os_error().is_some() {
            return Self::Io(e);
        }
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Self::Truncated {
                declared,
                actual: None,
            };
        }
        Self::Malformed(e)
    }

    /// Error returned when TAR entry content fails to decode: the scan stops,
    /// so no report can claim the uninspected entries are fine.
    pub fn into_tar_error(self, path: &Path) -> ArchiveError {
        match self {
            Self::Checksum | Self::Malformed(_) | Self::Truncated { .. } => {
                ArchiveError::InvalidArchive(format!(
                    "integrity check failed at {}: {self}",
                    path.display()
                ))
            }
            Self::DeclaredSizeOverrun { declared } => declared_size_exceeded(declared),
            Self::ResourceLimit(e) | Self::NotDecodable(e) => e,
            Self::Io(e) => ArchiveError::Io(e),
        }
    }
}

/// Result of decoding one payload.
#[derive(Debug)]
pub enum DecodeOutcome {
    Verified,
    Unverified(UnverifiedReason),
    Failed(DecodeFailure),
}

/// Whether decoding an entry is charged to the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Listing does not decode it by itself: charge the declared size.
    Declared,
    /// Listing decodes it anyway.
    Free,
}

/// How a TAR stream is checked after the entry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarTrailer {
    /// Plain TAR: require one more byte, ignore anything after it.
    Probe,
    /// Compressed (or unknown) stream: read to decoder EOF within the budget.
    DrainToDecoderEof,
}

/// Handle to one manifest entry's issue slot; only
/// [`IntegrityPass::begin_entry`] mints it, so a slot always refers to an entry
/// that exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot(usize);

#[derive(Debug)]
struct EntrySlot {
    issues: Vec<VerificationIssue>,
    admitted: bool,
}

/// What the pass hands to `verify_manifest`.
#[derive(Debug)]
pub struct IntegrityOutcome {
    pub entry_issues: Vec<Vec<VerificationIssue>>,
    pub archive_issues: Vec<VerificationIssue>,
    pub gaps: IntegrityGaps,
}

/// Decodes payloads during listing and collects the integrity issues.
pub struct IntegrityPass<'c> {
    config: &'c SecurityConfig<Validated>,
    quota: QuotaTracker,
    budget_remaining: u64,
    buffer: Box<CopyBuffer>,
    slots: Vec<EntrySlot>,
    archive_issues: Vec<VerificationIssue>,
    gaps: IntegrityGaps,
}

impl<'c> IntegrityPass<'c> {
    pub fn new(config: &'c SecurityConfig<Validated>, budget: DecompressionBudget) -> Self {
        Self {
            config,
            quota: QuotaTracker::new(),
            budget_remaining: budget.get(),
            buffer: Box::new(CopyBuffer::new()),
            slots: Vec::new(),
            archive_issues: Vec::new(),
            gaps: IntegrityGaps::default(),
        }
    }

    pub const fn config(&self) -> &'c SecurityConfig<Validated> {
        self.config
    }

    /// Opens the slot of the manifest entry about to be added and decides
    /// admission with the same quota and ratio checks `verify_manifest` runs.
    /// Returns the slot index, which equals the entry's manifest index.
    pub fn begin_entry(&mut self, size: u64, compression: &EntryCompression) -> Slot {
        let quota_ok = self.quota.reserve(size, self.config).is_ok();
        let ratio_ok = validate_entry_compression(compression, size, self.config).is_ok();
        self.slots.push(EntrySlot {
            issues: Vec::new(),
            admitted: quota_ok && ratio_ok,
        });
        Slot(self.slots.len() - 1)
    }

    pub fn is_admitted(&self, slot: Slot) -> bool {
        self.slots[slot.0].admitted
    }

    pub fn push_issue(&mut self, slot: Slot, issue: VerificationIssue) {
        self.slots[slot.0].issues.push(issue);
    }

    /// Counts unverified items that belong to no single entry.
    pub fn count_unverified(&mut self, reason: UnverifiedReason, items: u64) {
        self.gaps.count_items(reason, items);
    }

    /// Marks the entry at `path` as unverified, listing it in the report.
    pub fn mark_unverified(&mut self, reason: UnverifiedReason, path: &Path) {
        self.gaps.mark_entry(reason, path);
    }

    /// Reserves `bytes` of the budget; an entry that does not fit leaves the
    /// remaining budget untouched so later, smaller entries are still tried.
    pub fn try_charge(&mut self, bytes: u64) -> bool {
        match self.budget_remaining.checked_sub(bytes) {
            Some(left) => {
                self.budget_remaining = left;
                true
            }
            None => false,
        }
    }

    /// Decodes `reader` to its EOF, enforcing `declared` as an exact size.
    pub fn decode<R: Read + ?Sized>(
        &mut self,
        slot: Slot,
        reader: &mut R,
        declared: u64,
        charge: Charge,
    ) -> DecodeOutcome {
        if !self.is_admitted(slot) {
            return DecodeOutcome::Unverified(UnverifiedReason::ResourceLimit);
        }
        if charge == Charge::Declared && !self.try_charge(declared) {
            return DecodeOutcome::Unverified(UnverifiedReason::OverBudget);
        }
        match copy_bounded(reader, &mut io::sink(), &mut self.buffer, Some(declared)) {
            Ok(_) => DecodeOutcome::Verified,
            Err(e) => DecodeOutcome::Failed(DecodeFailure::from_copy(e, declared)),
        }
    }

    /// Copies `reader` to `writer` with the pass's buffer, enforcing
    /// `declared`.
    pub fn copy_into<R: Read + ?Sized, W: io::Write + ?Sized>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        declared: u64,
    ) -> std::result::Result<u64, DecodeFailure> {
        copy_bounded(reader, writer, &mut self.buffer, Some(declared))
            .map_err(|e| DecodeFailure::from_copy(e, declared))
    }

    /// Records an outcome against `slot`. The only place a [`DecodeFailure`]
    /// becomes an issue.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a failing disk read, which is not a property
    /// of the archive.
    pub fn record(&mut self, slot: Slot, path: &Path, outcome: DecodeOutcome) -> Result<()> {
        match outcome {
            DecodeOutcome::Verified => {}
            DecodeOutcome::Unverified(reason) => self.mark_unverified(reason, path),
            DecodeOutcome::Failed(failure) => self.record_failure(Some((slot, path)), failure)?,
        }
        Ok(())
    }

    /// The single table mapping a failure to an issue and an unverified count.
    /// `entry` is the owning entry, or `None` for an archive-level failure.
    fn record_failure(
        &mut self,
        entry: Option<(Slot, &Path)>,
        failure: DecodeFailure,
    ) -> Result<()> {
        let entry_path = entry.map(|(_, path)| path.to_path_buf());
        let (issue, unverified) = match failure {
            DecodeFailure::Io(e) => return Err(ArchiveError::Io(e)),
            DecodeFailure::Checksum
            | DecodeFailure::Malformed(_)
            | DecodeFailure::Truncated { .. } => (corrupt_issue(&failure, entry_path), None),
            DecodeFailure::DeclaredSizeOverrun { declared } => (
                VerificationIssue::from_error(&declared_size_exceeded(declared), entry_path),
                Some(UnverifiedReason::SizeCeiling),
            ),
            DecodeFailure::ResourceLimit(e) => (
                VerificationIssue::from_error(&e, entry_path),
                Some(UnverifiedReason::ResourceLimit),
            ),
            DecodeFailure::NotDecodable(e) => (
                VerificationIssue::from_error(&e, entry_path),
                Some(UnverifiedReason::NotDecodable),
            ),
        };
        match (entry, unverified) {
            (Some((slot, path)), Some(reason)) => {
                self.push_issue(slot, issue);
                self.mark_unverified(reason, path);
            }
            (Some((slot, _)), None) => self.push_issue(slot, issue),
            (None, reason) => {
                self.archive_issues.push(issue);
                if let Some(reason) = reason {
                    self.count_unverified(reason, 1);
                }
            }
        }
        Ok(())
    }

    /// Checks the TAR stream after the entry loop.
    ///
    /// A conforming archive always has bytes after the loop (the tar reader
    /// stops at the first zero block), so none left means the end marker is
    /// missing. Failures inside the trailer are archive-level.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a failing disk read.
    pub fn check_tar_trailer<R: Read>(&mut self, reader: &mut R, mode: TarTrailer) -> Result<()> {
        let outcome = match mode {
            TarTrailer::Probe => probe_one_byte(reader),
            TarTrailer::DrainToDecoderEof => self.drain_to_decoder_eof(reader),
        };
        match outcome {
            Ok(0) => self.count_unverified(UnverifiedReason::NoEndMarker, 1),
            Ok(_) => {}
            Err(TrailerError::OverBudget) => self.count_unverified(UnverifiedReason::OverBudget, 1),
            Err(TrailerError::Failed(failure)) => self.record_failure(None, failure)?,
        }
        Ok(())
    }

    fn drain_to_decoder_eof<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> std::result::Result<u64, TrailerError> {
        let allowance = self.budget_remaining.saturating_add(1);
        let drained = copy_bounded(
            &mut reader.take(allowance),
            &mut io::sink(),
            &mut self.buffer,
            None,
        )
        .map_err(|e| TrailerError::Failed(DecodeFailure::from_copy(e, 0)))?;
        if drained > self.budget_remaining {
            self.budget_remaining = 0;
            return Err(TrailerError::OverBudget);
        }
        self.budget_remaining -= drained;
        Ok(drained)
    }

    /// Adds the single archive-level `IntegrityIncomplete` issue when anything
    /// was left unverified, and returns the collected issues.
    pub fn finish(mut self) -> IntegrityOutcome {
        if let Some(message) = self.gaps.message() {
            self.archive_issues.push(VerificationIssue::new(
                IssueSeverity::Medium,
                IssueCategory::IntegrityIncomplete,
                message,
            ));
        }
        IntegrityOutcome {
            entry_issues: self.slots.into_iter().map(|s| s.issues).collect(),
            archive_issues: self.archive_issues,
            gaps: self.gaps,
        }
    }
}

enum TrailerError {
    OverBudget,
    Failed(DecodeFailure),
}

fn probe_one_byte<R: Read>(reader: &mut R) -> std::result::Result<u64, TrailerError> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(n) => return Ok(n as u64),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(TrailerError::Failed(DecodeFailure::from_read_error(e, 0))),
        }
    }
}

fn corrupt_issue(
    failure: &DecodeFailure,
    entry_path: Option<std::path::PathBuf>,
) -> VerificationIssue {
    let mut issue = VerificationIssue::new(
        IssueSeverity::High,
        IssueCategory::CorruptData,
        format!("Corrupt data: {failure}"),
    );
    issue.entry_path = entry_path;
    issue
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use std::path::PathBuf;

    use super::*;
    use crate::formats::tar_metadata_limit::DecoderMemoryExceeded;
    use crate::inspection::report::MAX_LISTED_UNVERIFIED;

    fn read_failure(e: io::Error) -> DecodeFailure {
        DecodeFailure::from_copy(CopyError::Read(e), 10)
    }

    fn pass_with_budget(config: &SecurityConfig<Validated>, bytes: u64) -> IntegrityPass<'_> {
        IntegrityPass::new(config, DecompressionBudget::try_from_bytes(bytes).unwrap())
    }

    #[test]
    fn test_classification_real_zip_checksum_mismatch() {
        let mut writer = zip::write::ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("a", options).unwrap();
        io::Write::write_all(&mut writer, b"MARKER").unwrap();
        let mut bytes = writer.finish().unwrap().into_inner();
        let at = bytes.windows(6).position(|w| w == b"MARKER").unwrap();
        bytes[at] ^= 1;

        let mut archive = zip::ZipArchive::new(io::Cursor::new(bytes)).unwrap();
        let mut entry = archive.by_index(0).unwrap();
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(6, &EntryCompression::Unknown);

        assert_matches!(
            pass.decode(slot, &mut entry, 6, Charge::Free),
            DecodeOutcome::Failed(DecodeFailure::Checksum)
        );
    }

    #[test]
    fn test_classification_zip_declared_size_overrun() {
        let e = io::Error::new(io::ErrorKind::InvalidData, ZIP_DECLARED_SIZE_EXCEEDED);
        assert_matches!(
            read_failure(e),
            DecodeFailure::DeclaredSizeOverrun { declared: 10 }
        );
    }

    #[test]
    fn test_classification_sevenz_checksum() {
        let e = io::Error::other(sevenz_rust2::Error::ChecksumVerificationFailed);
        assert_matches!(read_failure(e), DecodeFailure::Checksum);
    }

    #[test]
    fn test_classification_os_error_is_io() {
        assert_matches!(
            read_failure(io::Error::from_raw_os_error(5)),
            DecodeFailure::Io(_)
        );
    }

    #[test]
    fn test_classification_unexpected_eof_is_truncated() {
        let e = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert_matches!(
            read_failure(e),
            DecodeFailure::Truncated {
                declared: 10,
                actual: None
            }
        );
    }

    #[test]
    fn test_classification_decoder_memory_is_a_resource_limit() {
        let e = io::Error::new(io::ErrorKind::InvalidData, DecoderMemoryExceeded { max: 7 });
        assert_matches!(
            read_failure(e),
            DecodeFailure::ResourceLimit(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::DecoderMemory { max: 7 }
            })
        );
    }

    #[test]
    fn test_classification_other_read_errors_are_malformed() {
        let e = io::Error::new(io::ErrorKind::InvalidData, "bad block");
        assert_matches!(read_failure(e), DecodeFailure::Malformed(_));
    }

    #[test]
    fn test_classification_copy_size_errors() {
        assert_matches!(
            DecodeFailure::from_copy(CopyError::Overrun { declared: 3 }, 3),
            DecodeFailure::DeclaredSizeOverrun { declared: 3 }
        );
        assert_matches!(
            DecodeFailure::from_copy(
                CopyError::Short {
                    declared: 3,
                    actual: 1
                },
                3
            ),
            DecodeFailure::Truncated {
                declared: 3,
                actual: Some(1)
            }
        );
        assert_matches!(
            DecodeFailure::from_copy(CopyError::Overflow, 3),
            DecodeFailure::ResourceLimit(ArchiveError::QuotaExceeded { .. })
        );
    }

    #[test]
    fn test_tar_error_keeps_resource_limits_typed() {
        let limit = DecodeFailure::ResourceLimit(ArchiveError::QuotaExceeded {
            resource: crate::QuotaResource::DecoderMemory { max: 1 },
        });
        assert_matches!(
            limit.into_tar_error(Path::new("a")),
            ArchiveError::QuotaExceeded { .. }
        );
        assert_matches!(
            DecodeFailure::Io(io::Error::from_raw_os_error(5)).into_tar_error(Path::new("a")),
            ArchiveError::Io(_)
        );
        assert_matches!(
            DecodeFailure::Checksum.into_tar_error(Path::new("a")),
            ArchiveError::InvalidArchive(_)
        );
    }

    #[test]
    fn test_budget_is_first_fit_and_never_overdrawn() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = pass_with_budget(&config, 10);

        assert!(!pass.try_charge(11));
        assert!(pass.try_charge(4));
        assert!(!pass.try_charge(7));
        assert!(pass.try_charge(6));
        assert!(!pass.try_charge(1));
    }

    #[test]
    fn test_finish_without_unverified_items_adds_no_issue() {
        let config = SecurityConfig::default().validate().unwrap();
        let pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);

        assert!(pass.finish().archive_issues.is_empty());
    }

    #[test]
    fn test_finish_reports_one_medium_issue_listing_every_reason() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        pass.count_unverified(UnverifiedReason::OverBudget, 2);
        pass.count_unverified(UnverifiedReason::SolidPolicy, 1);
        pass.count_unverified(UnverifiedReason::NoEndMarker, 0);

        let outcome = pass.finish();
        assert_eq!(outcome.archive_issues.len(), 1);
        let issue = &outcome.archive_issues[0];
        assert_eq!(issue.severity, IssueSeverity::Medium);
        assert_eq!(issue.category, IssueCategory::IntegrityIncomplete);
        assert!(issue.message.contains("3 item(s)"), "{}", issue.message);
        assert!(issue.message.contains("over budget: 2"));
        assert!(!issue.message.contains("no end-of-archive"));
    }

    #[test]
    fn test_gaps_list_marked_entries_and_count_the_rest() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        pass.mark_unverified(UnverifiedReason::SolidPolicy, Path::new("a"));
        pass.mark_unverified(UnverifiedReason::OverBudget, Path::new("b"));
        pass.count_unverified(UnverifiedReason::NoEndMarker, 1);

        let outcome = pass.finish();
        let gaps = &outcome.gaps;
        assert_eq!(gaps.total(), 3);
        assert_eq!(gaps.count(UnverifiedReason::SolidPolicy), 1);
        assert_eq!(gaps.count(UnverifiedReason::NoEndMarker), 1);
        let listed: Vec<_> = gaps
            .entries()
            .iter()
            .map(|e| (e.path().to_path_buf(), e.reason()))
            .collect();
        assert_eq!(
            listed,
            [
                (PathBuf::from("a"), UnverifiedReason::SolidPolicy),
                (PathBuf::from("b"), UnverifiedReason::OverBudget),
            ]
        );
        assert_eq!(gaps.omitted(), 0);
        assert!(outcome.archive_issues[0].message.contains("3 item(s)"));
    }

    #[test]
    fn test_gaps_cap_listed_entries_and_count_the_overflow() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let over = 5;
        for i in 0..MAX_LISTED_UNVERIFIED + over {
            pass.mark_unverified(UnverifiedReason::OverBudget, Path::new(&i.to_string()));
        }

        let gaps = pass.finish().gaps;
        assert_eq!(gaps.entries().len(), MAX_LISTED_UNVERIFIED);
        assert_eq!(gaps.omitted(), over as u64);
        assert_eq!(
            gaps.count(UnverifiedReason::OverBudget),
            (MAX_LISTED_UNVERIFIED + over) as u64
        );
    }

    #[test]
    fn test_recorded_unverified_outcome_lists_the_entry() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(1, &EntryCompression::Unknown);

        pass.record(
            slot,
            Path::new("x"),
            DecodeOutcome::Unverified(UnverifiedReason::OverBudget),
        )
        .unwrap();

        let gaps = pass.finish().gaps;
        assert_eq!(gaps.entries()[0].path(), Path::new("x"));
    }

    #[test]
    fn test_trailer_probe_requires_one_byte() {
        let config = SecurityConfig::default().validate().unwrap();

        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        pass.check_tar_trailer(&mut io::Cursor::new(vec![0u8; 512]), TarTrailer::Probe)
            .unwrap();
        assert!(pass.finish().archive_issues.is_empty());

        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        pass.check_tar_trailer(&mut io::Cursor::new(Vec::new()), TarTrailer::Probe)
            .unwrap();
        assert_eq!(pass.finish().archive_issues.len(), 1);
    }

    #[test]
    fn test_trailer_drain_is_bounded_by_the_remaining_budget() {
        let config = SecurityConfig::default().validate().unwrap();

        let mut pass = pass_with_budget(&config, 10);
        pass.check_tar_trailer(
            &mut io::Cursor::new(vec![0u8; 10]),
            TarTrailer::DrainToDecoderEof,
        )
        .unwrap();
        assert!(pass.finish().archive_issues.is_empty());

        let mut pass = pass_with_budget(&config, 10);
        pass.check_tar_trailer(
            &mut io::Cursor::new(vec![0u8; 11]),
            TarTrailer::DrainToDecoderEof,
        )
        .unwrap();
        let outcome = pass.finish();
        assert_eq!(outcome.archive_issues.len(), 1);
        assert!(outcome.archive_issues[0].message.contains("over budget"));
    }

    #[test]
    fn test_trailer_drain_without_bytes_is_a_missing_end_marker() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);

        pass.check_tar_trailer(
            &mut io::Cursor::new(Vec::new()),
            TarTrailer::DrainToDecoderEof,
        )
        .unwrap();
        let outcome = pass.finish();
        assert!(
            outcome.archive_issues[0]
                .message
                .contains("no end-of-archive marker")
        );
    }

    #[test]
    fn test_rejected_entry_is_not_decoded() {
        let config = SecurityConfig::default()
            .with_max_file_size(4)
            .validate()
            .unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(8, &EntryCompression::Unknown);

        let outcome = pass.decode(slot, &mut io::Cursor::new(vec![0u8; 8]), 8, Charge::Free);
        assert_matches!(
            outcome,
            DecodeOutcome::Unverified(UnverifiedReason::ResourceLimit)
        );
    }

    #[test]
    fn test_decode_enforces_the_declared_size() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(4, &EntryCompression::Unknown);

        let short = pass.decode(slot, &mut io::Cursor::new(vec![0u8; 2]), 4, Charge::Free);
        assert_matches!(
            short,
            DecodeOutcome::Failed(DecodeFailure::Truncated {
                declared: 4,
                actual: Some(2)
            })
        );
        let long = pass.decode(slot, &mut io::Cursor::new(vec![0u8; 9]), 4, Charge::Free);
        assert_matches!(
            long,
            DecodeOutcome::Failed(DecodeFailure::DeclaredSizeOverrun { declared: 4 })
        );
        let exact = pass.decode(slot, &mut io::Cursor::new(vec![0u8; 4]), 4, Charge::Free);
        assert_matches!(exact, DecodeOutcome::Verified);
    }

    #[test]
    fn test_record_maps_failures_to_issues() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(1, &EntryCompression::Unknown);
        let path = Path::new("a");

        pass.record(slot, path, DecodeOutcome::Failed(DecodeFailure::Checksum))
            .unwrap();
        pass.record(
            slot,
            path,
            DecodeOutcome::Failed(DecodeFailure::DeclaredSizeOverrun { declared: 1 }),
        )
        .unwrap();
        let io_failure = pass.record(
            slot,
            path,
            DecodeOutcome::Failed(DecodeFailure::Io(io::Error::from_raw_os_error(5))),
        );
        assert_matches!(io_failure, Err(ArchiveError::Io(_)));

        let outcome = pass.finish();
        let categories: Vec<_> = outcome.entry_issues[0].iter().map(|i| i.category).collect();
        assert_eq!(
            categories,
            [IssueCategory::CorruptData, IssueCategory::SecurityPolicy]
        );
        assert_eq!(outcome.archive_issues.len(), 1);
    }
}
