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
use crate::ExistingFiles;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::formats::common;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::VettedDir;
use crate::formats::source_fault::ReadFaults;
use crate::formats::target::ExtractTarget;
use crate::formats::target::FileAdmission;
use crate::formats::target::FileRequest;
use crate::formats::target::HostParent;
use crate::formats::target::HostTarget;
use crate::formats::target::Tally;
use crate::security::admitted::EntrySize;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::context::ValidationContext;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::Occupant;
use crate::security::hardlink::HardlinkTarget;
use crate::security::validator::EntryPath;
use crate::security::validator::FileScreen;
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
    fn of(occupant: Option<Occupant>) -> Self {
        match occupant {
            None => Self::Vacant,
            Some(Occupant::File) => Self::RegularFile,
            Some(Occupant::Symlink) => Self::Symlink,
            Some(Occupant::Directory) => Self::Directory,
        }
    }

    /// Looks at `leaf` in `parent` without following a symlink, so a dangling
    /// link counts as occupied.
    fn probe(parent: &VettedDir, leaf: Leaf<'_>) -> std::io::Result<Self> {
        parent.probe(leaf).map(Self::of)
    }

    /// Path-based variant for the pre-pass, whose result only decides whether
    /// to skip or refuse an entry before anything is written; the write
    /// re-probes relative to its pinned parent.
    fn probe_path(dest_path: &Path) -> std::io::Result<Self> {
        Ok(Self::of(
            lstat_dest(dest_path)?.map(|meta| meta.file_type().into()),
        ))
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
    file: ValidatedFile<HostParent>,
    write_mode: WriteMode,
    parent: VettedDir,
}

/// A host destination for 7z extraction.
pub(super) struct SevenZHostTarget<'a> {
    inner: HostTarget<'a>,
}

impl<'a> SevenZHostTarget<'a> {
    /// Creates `output_dir` if needed and a target writing into it.
    pub(super) fn create(output_dir: &Path, config: &'a SecurityConfig) -> Result<Self> {
        Ok(Self {
            inner: HostTarget::create(output_dir, config)?,
        })
    }
}

impl ExtractTarget for SevenZHostTarget<'_> {
    type AdmittedFile = SevenZAdmittedFile;
    type Parent = HostParent;

    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<FileAdmission<SevenZAdmittedFile>> {
        let pending = match self.inner.screen_file(request)? {
            FileScreen::DisallowedExtension => {
                return tally
                    .record_extension_skip(request.path)
                    .map(FileAdmission::Skipped);
            }
            FileScreen::Pending(pending) => pending,
        };
        let safe_path = pending.path().clone();
        let (parent, leaf) = self
            .inner
            .dirs()
            .ensure_parent(self.inner.root(), &safe_path)?;
        // Owned because `admit_file` borrows the extractor mutably.
        let parent = parent.into_owned()?;

        let occupancy = DestOccupancy::probe(&parent, leaf)?;
        if occupancy.is_occupied() {
            match tally.options.existing_files {
                ExistingFiles::Skip => {
                    return tally
                        .record_duplicate_skip(safe_path.as_path())
                        .map(FileAdmission::Skipped);
                }
                ExistingFiles::Refuse => {
                    if self
                        .inner
                        .root()
                        .created()
                        .created_here(&parent, leaf, safe_path.as_path())
                    {
                        return tally
                            .record_duplicate_skip(safe_path.as_path())
                            .map(FileAdmission::Skipped);
                    }
                    return Err(common::destination_occupied(
                        self.inner.root().dest().as_path(),
                        safe_path.as_path(),
                    ));
                }
                ExistingFiles::Overwrite => {}
            }
        }
        let write_mode = occupancy.write_mode(safe_path.as_path())?;

        // Quota is reserved before anything is removed, so a refusal never
        // destroys a destination it could not replace.
        let file = self.inner.admit_file(pending)?;
        Ok(FileAdmission::Write(SevenZAdmittedFile {
            file,
            write_mode,
            parent,
        }))
    }

    fn validate_directory(&mut self, path: &Path, size: EntrySize) -> Result<SafePath<HostParent>> {
        self.inner.validate_directory(path, size)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<SafeSymlink<HostParent>> {
        self.inner.validate_symlink(path, target, size)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<ValidatedHardlink<HostParent>> {
        self.inner.validate_hardlink(path, target, size)
    }

    fn directory(&mut self, path: &SafePath<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        self.inner.directory(path, tally)
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        faults: ReadFaults<'_>,
        admitted: SevenZAdmittedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let SevenZAdmittedFile {
            file,
            write_mode,
            parent,
        } = admitted;
        let (path, permit, _mode) = file.into_parts();
        let (_, leaf) = Leaf::split(path.as_path())?;
        let written = match write_mode {
            WriteMode::CreateNew => write_file_direct(
                reader,
                faults,
                &parent,
                leaf,
                self.inner.copy_buffer_mut(),
                permit,
            )?,
            WriteMode::ReplaceRegular => write_file_with_permit(
                reader,
                faults,
                &parent,
                leaf,
                self.inner.copy_buffer_mut(),
                permit,
            )?,
        };
        self.inner.root().created().note(
            tally.options.existing_files,
            &parent,
            leaf,
            path.as_path(),
        );
        tally.record_file(written)
    }

    fn symlink(&mut self, symlink: &SafeSymlink<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        self.inner.symlink(symlink, tally)
    }

    fn hardlink(
        &mut self,
        link: &SafePath<HostParent>,
        target: &HardlinkTarget,
        counted: crate::security::quota::EntryCount,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        self.inner.hardlink(link, target, counted, tally)
    }
}

/// The host's pre-pass: paths against the disk as it is now.
struct HostPrePass<'a> {
    core: ValidatorCore<'a>,
    dest: &'a DestDir,
    config: &'a SecurityConfig,
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
        let dest_path = self.dest.join(safe_path);
        let occupancy = DestOccupancy::probe_path(&dest_path)?;
        if occupancy.is_occupied() {
            match self.options.existing_files {
                ExistingFiles::Skip => return Ok(FilePlan::Skip),
                ExistingFiles::Refuse => {
                    return Err(common::destination_occupied(
                        self.dest.as_path(),
                        safe_path.as_path(),
                    ));
                }
                ExistingFiles::Overwrite => {}
            }
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
        config: &SecurityConfig,
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
