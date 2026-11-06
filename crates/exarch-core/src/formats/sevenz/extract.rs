//! The one 7z extraction loop, shared by every destination.
//!
//! A destination is an [`ExtractTarget`] that also answers the pre-pass: the
//! checks that can refuse an archive from its file table alone, before the
//! target sees an entry. Admission, the pre-pass, the empty-archive
//! short-circuit and the decode loop are the same for the host filesystem and
//! for an entry sink; only the [`SevenZTarget`] hooks differ.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;

use super::SevenZArchive;
use super::StoredLinkTarget;
use super::classify::SevenZClass;
use super::classify::SevenZKind;
use super::classify::abort_with;
use super::classify::reparse_point_refusal;
use super::decode::decode_archive_entries;
use super::iter_sevenz_refusals;
use super::links::read_sevenz_link_target;
use super::lzma2::DecodeKnobs;
use super::push_anti_item_warning;
use crate::ArchiveError;
use crate::EntryPosition;
use crate::EntryTotal;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::formats::common;
use crate::formats::common::EntryCompleteGuard;
use crate::formats::source_fault::ReadFamily;
use crate::formats::source_fault::ReadFaults;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;
use crate::formats::target::ExtractTarget;
use crate::formats::target::FileAdmission;
use crate::formats::target::FileRequest;
use crate::formats::target::Tally;
use crate::security::Uncompressed;
use crate::security::admitted::EntrySize;
use crate::security::validator::EntryPath;
use crate::security::validator::NodeKind;
use crate::security::zipbomb::validate_entry_compression;
use crate::types::SafePath;
use crate::types::safe_symlink::require_symlinks_allowed;

/// A 7z archive that passed [`SevenZArchive::admit`] under `config`: solid
/// policy, decoder memory, coders and block layout.
///
/// Extraction goes through [`Self::extract_with`], which builds the target
/// from the admission's `config`, so the pre-pass, the decode and the target
/// use the one configuration. The token owns the archive borrow, so it cannot
/// be redeemed against another archive.
pub struct AdmittedSevenZ<'a, R: Read + Seek> {
    archive: &'a mut SevenZArchive<R>,
    config: &'a SecurityConfig,
}

impl<'a, R: Read + Seek> AdmittedSevenZ<'a, R> {
    /// Extracts into the target `make_target` builds from the admission's
    /// config.
    ///
    /// # Errors
    ///
    /// Returns the target's construction error, or the first extraction
    /// refusal.
    pub(crate) fn extract_with<T: SevenZTarget>(
        self,
        make_target: impl FnOnce(&'a SecurityConfig) -> Result<T>,
        options: SinkOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let mut target = make_target(self.config)?;
        self.archive
            .extract_admitted(self.config, &mut target, options, progress)
    }
}

/// What the pre-pass does with a file entry once its destination is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePlan {
    /// Reserve the file's quota.
    Reserve,
    /// Extraction will skip the entry as a duplicate, so it reserves nothing.
    Skip,
}

/// The destination-specific half of the pre-pass.
///
/// Each method is one place where the host filesystem and an entry sink
/// differ; the order of the checks around them is fixed by
/// [`SevenZArchive::run_pre_pass`].
pub trait PrePass {
    /// Validates an entry's path against the destination as it is now.
    fn validate_path(&mut self, path: &Path, kind: NodeKind) -> Result<EntryPath<SafePath>>;

    /// Checks a directory entry.
    fn directory(&mut self, path: &Path) -> Result<()>;

    /// Checks a symlink entry whose target is still undecoded.
    fn symlink(
        &mut self,
        link: &SafePath,
        path: &Path,
        file: &sevenz_rust2::ArchiveEntry,
    ) -> Result<()>;

    /// Checks a file entry against what already occupies its destination.
    fn file(&mut self, safe_path: &SafePath, path: &Path) -> Result<FilePlan>;

    /// Reserves quota for a symlink.
    fn reserve_symlink(&mut self, size: u64) -> Result<()>;

    /// Reserves quota for a file.
    fn reserve_file(&mut self, size: u64) -> Result<()>;
}

/// A destination the shared 7z loop can extract into.
pub trait SevenZTarget: ExtractTarget {
    /// Runs `run` against a fresh pre-pass over this destination.
    ///
    /// The pre-pass keeps its own quota, so the extraction that follows does
    /// not count an entry twice.
    fn with_pre_pass(
        &self,
        config: &SecurityConfig,
        options: SinkOptions,
        run: &mut dyn FnMut(&mut dyn PrePass) -> Result<()>,
    ) -> Result<()>;
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Admits the archive under `config`, or returns the first refusal.
    ///
    /// # Errors
    ///
    /// Returns the first admission refusal.
    pub(crate) fn admit<'a>(
        &'a mut self,
        config: &'a SecurityConfig,
    ) -> Result<AdmittedSevenZ<'a, R>> {
        if let Some(refusal) = iter_sevenz_refusals(&self.header, config).next() {
            return Err(refusal.into_error());
        }
        Ok(AdmittedSevenZ {
            archive: self,
            config,
        })
    }

    /// Extracts into `target`.
    ///
    /// Everything that can be refused from the file table alone (ratios,
    /// quotas, link policy, paths) is refused before the target sees an entry.
    fn extract_admitted<T: SevenZTarget>(
        &mut self,
        config: &SecurityConfig,
        target: &mut T,
        options: SinkOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        target.with_pre_pass(config, options, &mut |pre| self.run_pre_pass(config, pre))?;

        let total = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.class, SevenZClass::Present(_)))
            .count();
        let anti_items = self.anti_item_count();
        if total == 0 {
            let mut report = ExtractionReport::new();
            push_anti_item_warning(&mut report, anti_items);
            return Ok(report);
        }

        let report = self.decode_into(target, config, options, progress, total, anti_items)?;
        progress.on_complete();
        Ok(report)
    }

    /// The checks that need only the file table, in the order every
    /// destination applies them.
    fn run_pre_pass(&self, config: &SecurityConfig, pre: &mut dyn PrePass) -> Result<()> {
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(kind) = entry.class.present(&entry.name)? else {
                continue;
            };
            let path = PathBuf::from(common::normalize_entry_name(&entry.name));
            let safe_path = match pre.validate_path(&path, kind.node_kind())? {
                EntryPath::Root(_) => continue,
                EntryPath::Child(safe_path) => safe_path,
            };
            match kind {
                SevenZKind::Directory => pre.directory(&path)?,
                SevenZKind::ReparsePoint => return Err(reparse_point_refusal(&entry.name)),
                SevenZKind::UnixSymlink => {
                    validate_entry_compression(
                        &entry.compression,
                        Uncompressed(entry.size),
                        config,
                    )?;
                    require_symlinks_allowed(config)?;
                    pre.symlink(&safe_path, &path, &self.header.files()[index])?;
                    pre.reserve_symlink(entry.size)?;
                }
                SevenZKind::File => {
                    // The ratio is a property of the archive, not of the
                    // destination, so it is checked before the duplicate skip,
                    // matching what `verify` reports.
                    validate_entry_compression(
                        &entry.compression,
                        Uncompressed(entry.size),
                        config,
                    )?;
                    if !common::is_extension_allowed(&path, config) {
                        continue;
                    }
                    if pre.file(&safe_path, &path)? == FilePlan::Reserve {
                        pre.reserve_file(entry.size)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn decode_into<T: SevenZTarget>(
        &mut self,
        target: &mut T,
        config: &SecurityConfig,
        options: SinkOptions,
        progress: &mut dyn ProgressCallback,
        total: usize,
        anti_items: u64,
    ) -> Result<ExtractionReport> {
        let mut report = ExtractionReport::new();
        let mut pending_error: Option<ArchiveError> = None;
        let mut index = 0_usize;
        let is_solid = self.header.is_solid();
        let tap = SourceTap::default();
        let faults = ReadFaults::new(ReadFamily::SevenZ, Some(&tap));

        let mut each = |entry: &sevenz_rust2::ArchiveEntry,
                        reader: &mut dyn Read|
         -> std::result::Result<bool, sevenz_rust2::Error> {
            let kind = match SevenZClass::of(entry).present(&entry.name) {
                Ok(Some(kind)) => kind,
                Ok(None) => return Ok(true),
                Err(refusal) => return Err(abort_with(&mut pending_error, refusal)),
            };
            let path = PathBuf::from(common::normalize_entry_name(&entry.name));
            let position = EntryPosition::at_index(index, EntryTotal::Known(total));
            index = index.saturating_add(1);
            let mut guard = EntryCompleteGuard::try_start(&mut *progress, &path, position)
                .map_err(|error| abort_with(&mut pending_error, error))?;

            let outcome = {
                let mut tally = Tally {
                    report: &mut report,
                    options,
                    progress: guard.progress_mut(),
                };
                process_entry(target, entry, kind, &mut *reader, faults, &path, &mut tally)
            };
            // Entries of a solid block share one decoder stream: bytes a
            // skipped entry left unread would be served to the next entry.
            let outcome = outcome.and_then(|()| {
                if is_solid {
                    io::copy(&mut (&mut *reader).take(entry.size), &mut io::sink())
                        .map(drop)
                        .map_err(|error| faults.classify_read(error))
                } else {
                    Ok(())
                }
            });
            match outcome {
                Ok(()) => {
                    guard.complete();
                    Ok(true)
                }
                Err(error) => Err(abort_with(&mut pending_error, error)),
            }
        };

        let mut source = SourceRead::new(&mut self.source, tap.clone());
        let result = decode_archive_entries(
            &mut source,
            &self.header,
            config.parallel_decode,
            DecodeKnobs::production(),
            &mut each,
        );
        push_anti_item_warning(&mut report, anti_items);
        match result {
            Ok(()) => Ok(report),
            Err(error) => Err(ArchiveError::partial_or(
                report,
                pending_error
                    .take()
                    .unwrap_or_else(|| ArchiveError::from(error)),
            )),
        }
    }
}

pub(super) fn process_entry<T: ExtractTarget>(
    target: &mut T,
    entry: &sevenz_rust2::ArchiveEntry,
    kind: SevenZKind,
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    path: &Path,
    tally: &mut Tally<'_>,
) -> Result<()> {
    let size = EntrySize::new(Uncompressed(entry.size), None);
    match kind {
        SevenZKind::ReparsePoint => Err(reparse_point_refusal(&entry.name)),
        SevenZKind::UnixSymlink => {
            let link_target = match read_sevenz_link_target(reader, entry.size)? {
                Ok(StoredLinkTarget::Read(link_target)) => link_target,
                Ok(StoredLinkTarget::Oversized { bytes }) => {
                    return Err(common::symlink_target_too_large(bytes));
                }
                Err(failure) => return Err(failure.into_extract_error(&entry.name)),
            };
            let symlink = target.validate_symlink(path, &link_target, size)?;
            target.symlink(&symlink, tally)
        }
        SevenZKind::Directory => {
            let safe_path = target.validate_directory(path, size)?;
            target.directory(&safe_path, tally)
        }
        SevenZKind::File => {
            let request = FileRequest {
                path,
                size,
                mode: None,
            };
            if let FileAdmission::Write(admitted) = target.validate_file(request, tally)? {
                let mut reader = reader;
                target.file(&mut reader, faults, admitted, tally)?;
            }
            Ok(())
        }
    }
}
