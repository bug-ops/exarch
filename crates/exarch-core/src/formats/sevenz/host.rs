//! 7z extraction onto the host filesystem.
//!
//! [`SevenZHostTarget`] is a [`HostTarget`] that writes a file over an
//! existing regular file through a temp file and a rename, so a decode failure
//! cannot leave a truncated file where the original stood.

use std::io::Read;
use std::path::Path;

use super::extract::FilePlan;
use super::extract::PrePass;
use super::extract::SevenZTarget;
use super::write::lstat_dest;
use super::write::refuse_undecoded_target_in;
use super::write::write_file_direct;
use super::write::write_file_with_permit;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::config::Validated;
use crate::formats::common;
use crate::formats::target::ExtractTarget;
use crate::formats::target::FileAdmission;
use crate::formats::target::FileRequest;
use crate::formats::target::HostTarget;
use crate::formats::target::Tally;
use crate::security::admitted::EntrySize;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::context::ValidationContext;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::Occupant;
use crate::security::validator::EntryPath;
use crate::security::validator::NodeKind;
use crate::security::validator::ValidatorCore;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// What one lstat finds at a file's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestOccupancy {
    Vacant,
    RegularFile,
    Symlink,
    Directory,
}

impl DestOccupancy {
    /// Looks at `dest_path` without following a symlink, so a dangling link
    /// counts as occupied.
    fn probe(dest_path: &Path) -> std::io::Result<Self> {
        Ok(match lstat_dest(dest_path)? {
            None => Self::Vacant,
            Some(meta) if meta.file_type().is_symlink() => Self::Symlink,
            Some(meta) if meta.is_dir() => Self::Directory,
            Some(_) => Self::RegularFile,
        })
    }

    const fn is_occupied(self) -> bool {
        !matches!(self, Self::Vacant)
    }

    /// Refuses to unlink a pre-existing symlink and write under its name, as
    /// TAR and ZIP refuse it through `O_NOFOLLOW`. Elsewhere a symlink is
    /// replaced like a regular file.
    fn refuse_symlink(self, rel: &Path) -> Result<()> {
        if cfg!(unix) && self == Self::Symlink {
            return Err(common::symlink_at_dest_error(rel).into());
        }
        Ok(())
    }

    /// How to write over this occupant, or the refusal when it cannot be
    /// replaced.
    fn write_mode(self, rel: &Path) -> Result<WriteMode> {
        self.refuse_symlink(rel)?;
        match self {
            Self::Vacant => Ok(WriteMode::CreateNew),
            Self::Directory => Err(common::occupant_at_dest_error(rel, Occupant::Directory).into()),
            Self::RegularFile | Self::Symlink => Ok(WriteMode::ReplaceRegular),
        }
    }
}

/// How an admitted file reaches its destination.
#[derive(Debug, Clone, Copy)]
enum WriteMode {
    /// Nothing is there: open the destination itself with `O_EXCL`.
    CreateNew,
    /// A regular file is there: replace it through a temp file and a rename.
    ReplaceRegular,
}

/// A file the 7z host admitted, with the way to write it.
#[derive(Debug)]
pub(super) struct SevenZAdmittedFile {
    file: ValidatedFile,
    write_mode: WriteMode,
}

/// A host destination for 7z extraction.
pub(super) struct SevenZHostTarget<'a> {
    inner: HostTarget<'a>,
}

impl<'a> SevenZHostTarget<'a> {
    /// Creates `output_dir` if needed and a target writing into it.
    pub(super) fn create(output_dir: &Path, config: &'a SecurityConfig<Validated>) -> Result<Self> {
        Ok(Self {
            inner: HostTarget::create(output_dir, config)?,
        })
    }
}

impl ExtractTarget for SevenZHostTarget<'_> {
    type AdmittedFile = SevenZAdmittedFile;

    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<FileAdmission<SevenZAdmittedFile>> {
        let safe_path = self
            .inner
            .validate_path(request.path, NodeKind::NonDirectory)?
            .into_inner();
        let dest_path = self.inner.dest().join_path(safe_path.as_path());
        self.inner
            .dirs()
            .ensure_parent(self.inner.dest(), safe_path.as_path())?;

        let occupancy = DestOccupancy::probe(&dest_path)?;
        if occupancy.is_occupied() && tally.options.skip_duplicates {
            return tally.record_duplicate_skip().map(FileAdmission::Skipped);
        }
        let write_mode = occupancy.write_mode(safe_path.as_path())?;

        // Quota is reserved before anything is removed, so a refusal never
        // destroys a destination it could not replace.
        let permit = self.inner.reserve_file(request.size.uncompressed)?;
        Ok(FileAdmission::Write(SevenZAdmittedFile {
            file: ValidatedFile {
                path: safe_path,
                permit,
                mode: None,
            },
            write_mode,
        }))
    }

    fn validate_directory(&mut self, path: &Path, size: EntrySize) -> Result<SafePath> {
        self.inner.validate_directory(path, size)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<SafeSymlink> {
        self.inner.validate_symlink(path, target, size)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<ValidatedHardlink> {
        self.inner.validate_hardlink(path, target, size)
    }

    fn directory(&mut self, path: &SafePath, tally: &mut Tally<'_>) -> Result<()> {
        self.inner.directory(path, tally)
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        admitted: SevenZAdmittedFile,
        size: u64,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let SevenZAdmittedFile { file, write_mode } = admitted;
        let dest_path = self.inner.dest().join_path(file.path.as_path());
        let written = match write_mode {
            WriteMode::CreateNew => write_file_direct(
                reader,
                &dest_path,
                size,
                self.inner.copy_buffer_mut(),
                file.permit,
            )?,
            WriteMode::ReplaceRegular => write_file_with_permit(
                reader,
                &dest_path,
                size,
                self.inner.copy_buffer_mut(),
                file.permit,
            )?,
        };
        tally.report.bytes_written =
            common::checked_add_bytes(tally.report.bytes_written, written)?;
        tally.report.files_extracted += 1;
        if written > 0 {
            tally.progress.on_bytes_written(written);
        }
        Ok(())
    }

    fn symlink(&mut self, symlink: &SafeSymlink, tally: &mut Tally<'_>) -> Result<()> {
        self.inner.symlink(symlink, tally)
    }

    fn hardlink(
        &mut self,
        link: &SafePath,
        target: &SafePath,
        counted: crate::security::quota::EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()> {
        self.inner
            .hardlink(link, target, counted, tally, hardlink_duplicate_skips)
    }
}

/// The host's pre-pass: paths against the disk as it is now.
struct HostPrePass<'a> {
    core: ValidatorCore<'a>,
    dest: &'a DestDir,
    config: &'a SecurityConfig<Validated>,
    options: SinkOptions,
}

impl PrePass for HostPrePass<'_> {
    fn validate_path(&mut self, path: &Path, kind: NodeKind) -> Result<EntryPath<SafePath>> {
        let ctx: ValidationContext<HostFs> = self.core.context();
        self.core
            .validate_entry_path_in(path, kind, self.dest, &HostFs, &ctx)
    }

    fn directory(&mut self, _path: &Path) -> Result<()> {
        Ok(())
    }

    fn symlink(
        &mut self,
        link: &SafePath,
        _path: &Path,
        file: &sevenz_rust2::ArchiveEntry,
    ) -> Result<()> {
        common::require_symlink_creation()?;
        refuse_undecoded_target_in(link, file, self.dest, self.config, &HostFs)
    }

    fn file(&mut self, safe_path: &SafePath, _path: &Path) -> Result<FilePlan> {
        let dest_path = self.dest.join_path(safe_path.as_path());
        let occupancy = DestOccupancy::probe(&dest_path)?;
        if occupancy.is_occupied() && self.options.skip_duplicates {
            return Ok(FilePlan::Skip);
        }
        // Fail here too, before any entry is written, so the pre-pass keeps
        // its no-partial-extraction guarantee for this refusal.
        occupancy.refuse_symlink(safe_path.as_path())?;
        Ok(FilePlan::Reserve)
    }

    fn reserve_symlink(&mut self, size: u64) -> Result<()> {
        self.core.reserve_symlink(size)
    }

    fn reserve_file(&mut self, size: u64) -> Result<()> {
        self.core.reserve_file(size).map(drop)
    }
}

impl SevenZTarget for SevenZHostTarget<'_> {
    fn with_pre_pass(
        &self,
        config: &SecurityConfig<Validated>,
        options: SinkOptions,
        run: &mut dyn FnMut(&mut dyn PrePass) -> Result<()>,
    ) -> Result<()> {
        let mut pre = HostPrePass {
            core: ValidatorCore::new(config),
            dest: self.inner.dest(),
            config,
            options,
        };
        run(&mut pre)
    }
}
