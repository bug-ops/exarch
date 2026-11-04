//! Where a TAR or ZIP handler's validated entries go.
//!
//! The handler loops own every per-format gate (metadata budget, entry-type
//! refusal, encrypted entries, declared sizes, extension filter, two-pass
//! hardlinks). Only validation and the final write go through an
//! [`ExtractTarget`], so the host filesystem ([`HostTarget`]) and an
//! `EntrySink` run the same gates.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::zip_reuse::Retained;

use crate::ArchiveError;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::security::RawMode;
use crate::security::admitted::EntrySize;
use crate::security::admitted::PendingFile;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::context::ValidationContext;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::Occupant;
use crate::security::hardlink::HardlinkTarget;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::EntryCount;
use crate::security::validator::FileScreen;
use crate::security::validator::ValidatorCore;
use crate::sink::DuplicatePolicy;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;
#[cfg(not(any(unix, target_os = "wasi")))]
use crate::types::safe_path::Resolved;
#[cfg(any(unix, target_os = "wasi"))]
use crate::types::safe_path::Walked;
use crate::types::safe_symlink::resolve_through_symlinks;

use super::common;
use super::dir_walker::DirWalker;
use super::pinned_dir::PinnedRoot;
use super::pinned_dir::TempFileGuard;

/// The per-run counters a target updates while it writes.
pub struct Tally<'a> {
    pub(crate) report: &'a mut ExtractionReport,
    pub(crate) options: SinkOptions,
    /// File and symlink entries skipped as pre-existing duplicates.
    pub(crate) duplicate_skips: &'a mut u64,
    /// File entries skipped by the extension allowlist.
    pub(crate) extension_skips: &'a mut u64,
    pub(crate) progress: &'a mut dyn ProgressCallback,
}

impl Tally<'_> {
    /// Counts one entry skipped as a pre-existing duplicate.
    ///
    /// A target that skips a file at admission returns the token as
    /// [`FileAdmission::Skipped`]; other skip sites count through this method
    /// without one.
    ///
    /// # Errors
    ///
    /// Returns an error when the skipped-files counter would overflow.
    pub(crate) fn record_duplicate_skip(&mut self) -> Result<SkipRecorded> {
        common::checked_increment_files_skipped(self.report)?;
        *self.duplicate_skips = self.duplicate_skips.saturating_add(1);
        Ok(SkipRecorded(()))
    }

    /// Counts one file skipped by the extension allowlist.
    ///
    /// # Errors
    ///
    /// Returns an error when the skipped-files counter would overflow.
    pub(crate) fn record_extension_skip(&mut self) -> Result<SkipRecorded> {
        common::checked_increment_files_skipped(self.report)?;
        *self.extension_skips = self.extension_skips.saturating_add(1);
        Ok(SkipRecorded(()))
    }

    /// Counts one written file of `written` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when a counter would overflow.
    pub(crate) fn record_file(&mut self, written: u64) -> Result<()> {
        common::record_file_written(self.report, self.progress, written)
    }
}

/// What [`Tally`]'s `record_*_skip` methods return once a file is counted as
/// skipped, so a target that skips in `validate_file` has to count it.
#[derive(Debug)]
pub struct SkipRecorded(());

/// A file entry as a target is asked to admit it.
#[derive(Debug, Clone, Copy)]
pub struct FileRequest<'p> {
    pub(crate) path: &'p Path,
    pub(crate) size: EntrySize,
    pub(crate) mode: Option<RawMode>,
}

/// A target's decision on a requested file.
#[derive(Debug)]
pub enum FileAdmission<A> {
    /// The file is admitted and is to be written with `A`.
    Write(A),
    /// The file was skipped (a duplicate, or a disallowed extension).
    Skipped(SkipRecorded),
}

/// How a [`HostTarget`] has the parent directory of every path it validates
/// vetted: by the directory walker at write time where the root is pinned.
#[cfg(any(unix, target_os = "wasi"))]
pub type HostParent = Walked;
/// How a [`HostTarget`] has the parent directory of every path it validates
/// vetted: by the validator, where no pinned root exists.
#[cfg(not(any(unix, target_os = "wasi")))]
pub type HostParent = Resolved;

/// The validation and write half of an extraction.
pub trait ExtractTarget {
    /// How the parent directory of every path this target validates is vetted,
    /// which decides how the target may write it.
    type Parent: ParentCheck;

    /// What a target needs to write a file it admitted.
    type AdmittedFile;

    /// Validates a regular file's path, then skips it when its extension is
    /// disallowed or it duplicates an existing path, or else reserves its size
    /// against the quota.
    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<FileAdmission<Self::AdmittedFile>>;

    /// Validates a directory entry.
    fn validate_directory(
        &mut self,
        path: &Path,
        size: EntrySize,
    ) -> Result<SafePath<Self::Parent>>;

    /// Validates a symlink entry and its target.
    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<SafeSymlink<Self::Parent>>;

    /// Validates a hardlink entry for the second pass.
    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<ValidatedHardlink<Self::Parent>>;

    /// Creates a validated directory.
    fn directory(&mut self, path: &SafePath<Self::Parent>, tally: &mut Tally<'_>) -> Result<()>;

    /// Streams an admitted file from `reader`, capped at the size its quota
    /// permit reserved.
    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        admitted: Self::AdmittedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()>;

    /// Writes an admitted file from output the ZIP census kept, which was
    /// checked against the entry's length and CRC-32. The default streams it
    /// through [`Self::file`]; a target that can take the buffer as it is
    /// overrides it.
    fn file_retained(
        &mut self,
        retained: Retained<'_>,
        admitted: Self::AdmittedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        match retained {
            Retained::Bytes(bytes) => self.file(&mut bytes.as_slice(), admitted, tally),
            Retained::Spooled(mut reader) => self.file(&mut reader, admitted, tally),
        }
    }

    /// Creates a validated symlink.
    fn symlink(&mut self, symlink: &SafeSymlink<Self::Parent>, tally: &mut Tally<'_>)
    -> Result<()>;

    /// Materializes a hardlink in the second pass, once every target exists.
    fn hardlink(
        &mut self,
        link: &SafePath<Self::Parent>,
        target: &HardlinkTarget,
        counted: EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()>;
}

/// A validation context whose parent probe the directory walker takes over
/// where the root is pinned: every path validated with it is written through
/// `DirWalker` on `root`, which vets each parent at write time.
///
/// Takes the core and root as separate borrows, so a caller can validate
/// through `&mut` core while the context holds the root.
#[cfg(any(unix, target_os = "wasi"))]
pub(super) fn host_context<'r>(
    core: &ValidatorCore<'_>,
    root: &'r PinnedRoot,
) -> ValidationContext<'r, HostFs, HostParent> {
    core.context::<HostFs>()
        .with_walker(root.backs_parent_probe())
}

/// A validation context for a target without a pinned root: the validator
/// resolves each parent itself.
#[cfg(not(any(unix, target_os = "wasi")))]
pub(super) fn host_context<'r>(
    core: &ValidatorCore<'_>,
    _root: &'r PinnedRoot,
) -> ValidationContext<'r, HostFs, HostParent> {
    core.context::<HostFs>()
}

/// Extraction onto the real filesystem.
pub struct HostTarget<'a> {
    root: PinnedRoot,
    dirs: DirWalker,
    copy_buffer: CopyBuffer,
    core: ValidatorCore<'a>,
    config: &'a SecurityConfig<Validated>,
}

impl<'a> HostTarget<'a> {
    /// Creates `output_dir` if needed and a target writing into it.
    pub(crate) fn create(output_dir: &Path, config: &'a SecurityConfig<Validated>) -> Result<Self> {
        Ok(Self {
            root: PinnedRoot::open(DestDir::new_or_create(output_dir.to_path_buf())?)?,
            dirs: DirWalker::new(config),
            copy_buffer: CopyBuffer::new(),
            core: ValidatorCore::new(config),
            config,
        })
    }

    pub(super) const fn dest(&self) -> &DestDir {
        self.root.dest()
    }

    pub(super) const fn root(&self) -> &PinnedRoot {
        &self.root
    }

    pub(super) fn copy_buffer_mut(&mut self) -> &mut CopyBuffer {
        &mut self.copy_buffer
    }

    pub(super) const fn dirs(&self) -> DirWalker {
        self.dirs
    }

    /// Validates a file's path and applies the extension allowlist, leaving
    /// quota to the caller.
    pub(super) fn screen_file(&self, request: FileRequest<'_>) -> Result<FileScreen<HostParent>> {
        let ctx = host_context(&self.core, &self.root);
        self.core.screen_file_path_in(
            request.path,
            request.size,
            request.mode,
            self.root.dest(),
            &HostFs,
            &ctx,
        )
    }

    /// Reserves the quota of a screened file.
    pub(super) fn admit_file(
        &mut self,
        pending: PendingFile<HostParent>,
    ) -> Result<ValidatedFile<HostParent>> {
        self.core.admit_file(pending)
    }
}

impl ExtractTarget for HostTarget<'_> {
    type AdmittedFile = ValidatedFile<HostParent>;
    type Parent = HostParent;

    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<FileAdmission<ValidatedFile<HostParent>>> {
        match self.screen_file(request)? {
            FileScreen::DisallowedExtension => {
                tally.record_extension_skip().map(FileAdmission::Skipped)
            }
            FileScreen::Pending(pending) => self.admit_file(pending).map(FileAdmission::Write),
        }
    }

    fn validate_directory(&mut self, path: &Path, size: EntrySize) -> Result<SafePath<HostParent>> {
        let ctx = host_context(&self.core, &self.root);
        self.core
            .validate_directory_in(path, size, self.root.dest(), &HostFs, &ctx)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<SafeSymlink<HostParent>> {
        let ctx = host_context(&self.core, &self.root);
        self.core
            .validate_symlink_in(path, target, size, self.root.dest(), &HostFs, &ctx)
            .map(|validated| validated.symlink)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<ValidatedHardlink<HostParent>> {
        let ctx = host_context(&self.core, &self.root);
        self.core
            .validate_hardlink_in(path, target, size, self.root.dest(), &HostFs, &ctx)
    }

    fn directory(&mut self, path: &SafePath<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        common::create_directory(path, &self.root, tally.report, self.dirs)
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        admitted: ValidatedFile<HostParent>,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let (path, permit, mode) = admitted.into_parts();
        common::extract_file_with_permit(
            reader,
            &path,
            mode,
            permit,
            &self.root,
            tally.report,
            &mut self.copy_buffer,
            self.dirs,
            tally.options,
            tally.duplicate_skips,
            tally.progress,
        )
    }

    fn symlink(&mut self, symlink: &SafeSymlink<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        common::create_symlink(
            symlink,
            &self.root,
            tally.report,
            self.dirs,
            tally.options,
            tally.duplicate_skips,
        )
    }

    /// Creates a hardlink in the second pass by copying content.
    ///
    /// Uses a content copy instead of `fs::hard_link` to avoid shared-inode
    /// corruption: a real OS hardlink would allow a subsequent write to
    /// `link_path` to silently overwrite `target_path` (GHSA-2367-c296-3mp2
    /// variant, issue #130).
    ///
    /// # Security - Symlink-at-Destination Rejection (issue #467)
    ///
    /// The link is created with `O_EXCL | O_NOFOLLOW` relative to its pinned
    /// parent directory, which atomically fails with `AlreadyExists` for any
    /// pre-existing name: a symlink (dangling or not), a file or a directory.
    /// A separate `exists()` probe would report a dangling symlink as absent
    /// and could be raced.
    ///
    /// # Security - Target Read TOCTOU and Quota TOCTOU (issues #467, #818)
    ///
    /// Hardlinks are validated in two passes, and nothing re-validates the
    /// target between them, so the target is opened once, relative to its
    /// pinned parent directory, with `O_NOFOLLOW | O_NONBLOCK`. The handle is
    /// checked to be a regular file (a FIFO swapped in cannot stall the open
    /// or the read); the quota reservation is sized from that handle's
    /// `fstat`, and the copy reads from the same handle with the `fstat` size
    /// as an exact ceiling, so a target that grows afterwards fails closed
    /// instead of writing past the reservation.
    ///
    /// The link is created with the target's permission bits sanitized like an
    /// archive mode (no setuid, setgid or, unless allowed, world-write bits)
    /// and set on the open descriptor before any byte is written, so a target
    /// in the destination that was never extracted by this run cannot hand a
    /// wider mode to its copy, and a private target is never readable through
    /// the copy while it is being written.
    ///
    /// A symlink at the target is not automatically rejected: a hardlink may
    /// legitimately point at a symlink created earlier in the same extraction.
    /// It is resolved with the containment check pass one already trusts and
    /// the resolved, symlink-free path is walked again with every symlink
    /// refused. A resolution that leaves `dest` is reported as
    /// `HardlinkEscape`.
    fn hardlink(
        &mut self,
        link: &SafePath<HostParent>,
        target: &HardlinkTarget,
        counted: EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()> {
        let OpenedTarget {
            file: target_file,
            len: target_size,
            mode: target_mode,
        } = self.open_hardlink_target(link, target)?;
        // The target may be a pre-existing file of the destination, so its mode
        // is sanitized like an archive mode: never setuid, setgid or (unless
        // allowed) world-writable, and never wider than the target.
        let link_mode =
            target_mode.map(|mode| sanitize_permissions(RawMode::new(mode), self.config));

        let (link_dir, link_leaf) = self.dirs.ensure_parent(&self.root, link)?;
        let link_file = match link_dir.create_new(link_leaf, link_mode) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if tally.options.duplicate_policy() == DuplicatePolicy::Skip {
                    common::checked_increment_files_skipped(tally.report)?;
                    *hardlink_duplicate_skips = hardlink_duplicate_skips.saturating_add(1);
                    return Ok(());
                }
                return Err(ArchiveError::InvalidArchive(format!(
                    "duplicate entry: {}",
                    link.as_path().display()
                )));
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };
        let cleanup_guard = TempFileGuard::new(&link_dir, link_leaf);

        // Every hardlink copies the target's real bytes to a new inode, so it
        // must be charged against the same quota tracker as regular files
        // (issue #426): otherwise N hardlinks to one small file extract N
        // full copies with no size enforcement. The entry itself was counted
        // in pass one (`counted`), so a skipped duplicate keeps its count
        // slot but is charged no bytes, and the pending list is bounded by
        // `max_file_count` before anything is copied. The permit is consumed
        // by value below, so this charge cannot be spent twice.
        let permit = self.core.charge_hardlink(counted, target_size)?;

        // Copy content between the two handles opened above. Any subsequent
        // write to the link cannot corrupt the target because they are
        // separate files.
        let bytes_copied = common::copy_file_content_with_permit(
            target_file,
            link_file,
            &mut self.copy_buffer,
            permit,
        )?;
        cleanup_guard.persist();

        tally.record_file(bytes_copied)
    }
}

impl HostTarget<'_> {
    /// Opens the content source of a hardlink and returns it with its `fstat`
    /// size and permission bits.
    fn open_hardlink_target(
        &self,
        link: &SafePath<HostParent>,
        target: &HardlinkTarget,
    ) -> Result<OpenedTarget> {
        let file = if target.has_parent_dir() {
            // A validated target may step out of a directory it entered
            // (`d/../f`); only the resolved form can be walked by name.
            self.open_through_symlink(link, target)?
        } else {
            self.open_direct(link, target)?
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(ArchiveError::InvalidArchive(format!(
                "hardlink target is not a regular file: {}",
                target.as_path().display()
            )));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(meta.permissions().mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let mode = None;
        Ok(OpenedTarget {
            len: meta.len(),
            mode,
            file,
        })
    }

    /// Opens a hardlink target by name, falling back to its resolved location
    /// when the final component is a symlink.
    fn open_direct(&self, link: &SafePath<HostParent>, target: &HardlinkTarget) -> Result<File> {
        let missing = || hardlink_target_missing(target.as_path());
        let (dir, leaf) = match self.dirs.open_parent(&self.root, target.as_path()) {
            Ok(opened) => opened,
            // A pre-existing symlinked directory in the chain is read through
            // like a leaf symlink: resolved, checked for containment in `dest`
            // and walked again with every symlink refused.
            Err(_) if self.has_symlink_parent(target) => {
                return self.open_through_symlink(link, target);
            }
            Err(err) => return Err(not_found_as(err, missing)),
        };
        match dir.open_read(leaf) {
            Ok(file) => Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing()),
            Err(e) => match dir.probe(leaf) {
                Ok(Some(Occupant::Symlink)) => self.open_through_symlink(link, target),
                _ => Err(ArchiveError::Io(e)),
            },
        }
    }

    /// Whether a parent component of `target` is a symlink right now. Only
    /// picks the route: the resolved walk that follows enforces containment
    /// and refuses any symlink by file descriptor.
    fn has_symlink_parent(&self, target: &HardlinkTarget) -> bool {
        target.parent_probes(self.root.dest()).any(|parent| {
            parent
                .lstat()
                .is_ok_and(|meta| meta.file_type().is_symlink())
        })
    }

    /// Opens a hardlink target through its resolved, symlink-free location:
    /// a symlink created earlier in this extraction, or a path with `..`.
    fn open_through_symlink(
        &self,
        link: &SafePath<HostParent>,
        target: &HardlinkTarget,
    ) -> Result<File> {
        let missing = || hardlink_target_missing(target.as_path());
        // The path-based `exists` only picks the error: a dangling link is a
        // missing target, not an escape.
        if !target.probe_under(self.root.dest()).exists() {
            return Err(missing());
        }
        let escape = || ArchiveError::HardlinkEscape {
            path: link.as_path().to_path_buf(),
        };
        let dest = self.root.dest();
        let resolved =
            resolve_through_symlinks(dest.as_path(), target.as_path(), dest, link.as_path())
                .map_err(|_| escape())?;
        let inside = resolved
            .strip_prefix(dest.as_path())
            .map_err(|_| escape())?;
        let (dir, leaf) = self
            .dirs
            .open_resolved_parent(&self.root, inside)
            .map_err(|e| not_found_as(e, missing))?;
        match dir.open_read(leaf) {
            Ok(file) => Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(missing()),
            Err(e) => Err(ArchiveError::Io(e)),
        }
    }
}

/// A hardlink's content source, as `fstat` saw it.
struct OpenedTarget {
    file: File,
    len: u64,
    /// The permission bits (including setuid, setgid and sticky); `None` where
    /// the platform has none.
    mode: Option<u32>,
}

/// Replaces an I/O `NotFound` with `missing()`; any other error is unchanged.
fn not_found_as(err: ArchiveError, missing: impl FnOnce() -> ArchiveError) -> ArchiveError {
    match err {
        ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => missing(),
        other => other,
    }
}
