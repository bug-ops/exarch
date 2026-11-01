//! 7z extraction into an [`ExtractTarget`] other than the host filesystem.
//!
//! The gates are the host's: admission, the ratio and quota pre-validation, the
//! entry-kind refusals, the name-length limits of the path model, the
//! link-target read, the solid drain. Only the
//! destination differs: the pre-validation runs against an empty in-memory tree
//! instead of the disk, because nothing can occupy a sink before the first
//! entry.

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
use super::push_skip_warnings;
use super::write::refuse_undecoded_target_in;
use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::PathModel;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::formats::common;
use crate::formats::common::EntryCompleteGuard;
use crate::formats::target::ExtractTarget;
use crate::formats::target::Tally;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::validator::EntryPath;
use crate::security::validator::ValidatedEntryType;
use crate::security::validator::ValidatorCore;
use crate::security::zipbomb::validate_entry_compression;
use crate::types::EntryType;
use crate::types::safe_symlink::require_symlinks_allowed;

impl<R: Read + Seek> SevenZArchive<R> {
    /// Extracts into `target`, validating paths under `model`.
    ///
    /// Everything that can be refused from the file table alone (admission,
    /// ratios, quotas, link policy, paths) is refused before the target sees
    /// an entry.
    pub(crate) fn extract_into<T: ExtractTarget>(
        &mut self,
        target: &mut T,
        model: PathModel,
        config: &SecurityConfig<Validated>,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        if let Some(refusal) = iter_sevenz_refusals(&self.header, config).next() {
            return Err(refusal.into_error());
        }
        self.prevalidate_for_target(model, config)?;

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

        let report = self.decode_into(
            target,
            config,
            options.skip_duplicates,
            progress,
            total,
            anti_items,
        )?;
        progress.on_complete();
        Ok(report)
    }

    /// The host's pre-validation, against an empty tree.
    ///
    /// Name lengths are checked for the entries delivery would validate (files
    /// with a disallowed extension are skipped there). The length of the path
    /// an entry lands at after earlier symlinks resolve stays a delivery-time
    /// check, because 7z link targets are undecoded here.
    fn prevalidate_for_target(
        &self,
        model: PathModel,
        config: &SecurityConfig<Validated>,
    ) -> Result<()> {
        let root = VirtualRoot::new();
        let tree = VirtualTree::new(
            &root,
            model,
            NodeBudget::from_config(config),
            CollisionRecording::Discard,
        );
        let mut core = ValidatorCore::new(config);
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(kind) = entry.class.present(&entry.name)? else {
                continue;
            };
            let path = PathBuf::from(common::normalize_entry_name(&entry.name));
            let ctx = core.context::<VirtualTree>();
            let safe_path =
                match core.validate_entry_path_in(&path, kind.node_kind(), &root, &tree, &ctx)? {
                    EntryPath::Root(_) => continue,
                    EntryPath::Child(safe_path) => safe_path,
                };
            match kind {
                SevenZKind::Directory => check_name_lengths(model, &path)?,
                SevenZKind::ReparsePoint => return Err(reparse_point_refusal(&entry.name)),
                SevenZKind::UnixSymlink => {
                    check_name_lengths(model, &path)?;
                    validate_entry_compression(&entry.compression, entry.size, config)?;
                    require_symlinks_allowed(config)?;
                    refuse_undecoded_target_in(
                        &safe_path,
                        &self.header.files()[index],
                        &root,
                        config,
                        &tree,
                    )?;
                    core.reserve_symlink(entry.size)?;
                }
                SevenZKind::File => {
                    if common::is_extension_allowed(&path, config) {
                        check_name_lengths(model, &path)?;
                    }
                    validate_entry_compression(&entry.compression, entry.size, config)?;
                    core.reserve_file(entry.size).map(drop)?;
                }
            }
        }
        Ok(())
    }

    fn decode_into<T: ExtractTarget>(
        &mut self,
        target: &mut T,
        config: &SecurityConfig<Validated>,
        skip_duplicates: bool,
        progress: &mut dyn ProgressCallback,
        total: usize,
        anti_items: u64,
    ) -> Result<ExtractionReport> {
        let mut report = ExtractionReport::new();
        let mut duplicate_skips = 0_u64;
        let mut disallowed_extension_skips = 0_u64;
        let mut pending_error: Option<ArchiveError> = None;
        let mut index = 0_usize;
        let is_solid = self.header.is_solid();

        let mut each = |entry: &sevenz_rust2::ArchiveEntry,
                        reader: &mut dyn Read|
         -> std::result::Result<bool, sevenz_rust2::Error> {
            let kind = match SevenZClass::of(entry).present(&entry.name) {
                Ok(Some(kind)) => kind,
                Ok(None) => return Ok(true),
                Err(refusal) => return Err(abort_with(&mut pending_error, refusal)),
            };
            let path = PathBuf::from(common::normalize_entry_name(&entry.name));
            index = index.saturating_add(1);
            progress.on_entry_start(&path, total, index);
            let mut guard = EntryCompleteGuard::new(&mut *progress, &path);

            let outcome = {
                let mut tally = Tally {
                    report: &mut report,
                    skip_duplicates,
                    duplicate_skips: &mut duplicate_skips,
                    progress: guard.progress_mut(),
                };
                process_entry(
                    target,
                    entry,
                    kind,
                    &mut *reader,
                    &path,
                    config,
                    &mut disallowed_extension_skips,
                    &mut tally,
                )
            };
            // Entries of a solid block share one decoder stream: bytes a
            // skipped entry left unread would be served to the next entry.
            let outcome = outcome.and_then(|()| {
                if is_solid {
                    io::copy(&mut (&mut *reader).take(entry.size), &mut io::sink())
                        .map(drop)
                        .map_err(ArchiveError::Io)
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

        let result = decode_archive_entries(
            &mut self.source,
            &self.header,
            config.parallel_decode,
            DecodeKnobs::production(),
            &mut each,
        );
        push_skip_warnings(
            &mut report,
            (duplicate_skips, disallowed_extension_skips),
            anti_items,
        );
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

fn check_name_lengths(model: PathModel, path: &Path) -> Result<()> {
    model.check_name_lengths(path).map_err(ArchiveError::Io)
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the host entry processor; a parameter struct adds indirection"
)]
fn process_entry<T: ExtractTarget>(
    target: &mut T,
    entry: &sevenz_rust2::ArchiveEntry,
    kind: SevenZKind,
    reader: &mut dyn Read,
    path: &Path,
    config: &SecurityConfig<Validated>,
    disallowed_extension_skips: &mut u64,
    tally: &mut Tally<'_>,
) -> Result<()> {
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
            let validated = target.validate(
                path,
                &EntryType::Symlink {
                    target: link_target,
                },
                entry.size,
                None,
                None,
            )?;
            if let ValidatedEntryType::Symlink(symlink) = validated.entry_type() {
                target.symlink(symlink, tally)?;
            }
            Ok(())
        }
        SevenZKind::Directory => {
            let validated = target.validate(path, &EntryType::Directory, entry.size, None, None)?;
            target.directory(validated.safe_path(), tally)
        }
        SevenZKind::File => {
            if !common::check_extension_allowed(
                path,
                config,
                tally.report,
                disallowed_extension_skips,
            ) {
                return Ok(());
            }
            let validated = target.validate(path, &EntryType::File, entry.size, None, None)?;
            let (safe_path, entry_type, mode) = validated.into_parts();
            let ValidatedEntryType::File(permit) = entry_type else {
                return Err(ArchiveError::violation(
                    "validate_entry(EntryType::File) returned a non-File variant".into(),
                ));
            };
            let mut reader = reader;
            target.file(&mut reader, &safe_path, mode, permit, entry.size, tally)
        }
    }
}
