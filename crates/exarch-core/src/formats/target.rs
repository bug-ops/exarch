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
use crate::ExistingFiles;
use crate::ExtractionReport;
use crate::Malformation;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::SkipKind;
use crate::copy::CopyBuffer;
use crate::security::RawMode;
use crate::security::admitted::EntrySize;
use crate::security::admitted::PendingFile;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::context::ValidationContext;
use crate::security::fs_view::FsView;
use crate::security::fs_view::LinkBase;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::PinnedHostFs;
use crate::security::hardlink::HardlinkTarget;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::EntryCount;
use crate::security::validator::Gated;
use crate::security::validator::ValidatorCore;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;
#[cfg(not(any(unix, target_os = "wasi")))]
use crate::types::safe_path::Resolved;
#[cfg(any(unix, target_os = "wasi"))]
use crate::types::safe_path::Walked;

use super::common;
use super::dir_walker::DirWalker;
use super::pinned_dir::PinnedRoot;
use super::pinned_dir::TempFileGuard;
use super::source_fault::ReadFaults;

/// The per-run counters a target updates while it writes.
pub struct Tally<'a> {
    pub(crate) report: &'a mut ExtractionReport,
    pub(crate) options: SinkOptions,
    pub(crate) progress: &'a mut dyn ProgressCallback,
}

impl Tally<'_> {
    /// Counts one entry skipped as a pre-existing duplicate.
    ///
    /// A target that skips a file at admission returns the token as
    /// [`Admission::Skipped`]; other skip sites count through this method
    /// without one.
    ///
    /// # Errors
    ///
    /// Returns an error when the skipped-files counter would overflow.
    pub(crate) fn record_duplicate_skip(&mut self, path: &Path) -> Result<SkipRecorded> {
        common::record_duplicate_skip(self.report, path)?;
        Ok(SkipRecorded(()))
    }

    /// Counts one entry the gate left out, for `kind`.
    ///
    /// # Errors
    ///
    /// Returns an error when the skipped-files counter would overflow.
    pub(crate) fn record_skip(&mut self, kind: SkipKind, path: &Path) -> Result<SkipRecorded> {
        common::record_skip(self.report, kind, path)?;
        Ok(SkipRecorded(()))
    }

    /// Turns the gate's decision into an admission, counting a skip.
    ///
    /// # Errors
    ///
    /// Returns an error when the skipped-files counter would overflow.
    pub(crate) fn admission<A>(&mut self, gated: Gated<A>, path: &Path) -> Result<Admission<A>> {
        match gated {
            Gated::Admit(admitted) => Ok(Admission::Admit(admitted)),
            Gated::Skip(kind) => self.record_skip(kind, path).map(Admission::Skipped),
        }
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

/// A target's decision on a requested entry.
#[derive(Debug)]
pub enum Admission<A> {
    /// The entry is admitted and is to be written with `A`.
    Admit(A),
    /// The entry was skipped (a duplicate, a disallowed extension, or left out
    /// by the selection) and counted.
    Skipped(SkipRecorded),
}

impl<A> Admission<A> {
    /// The admitted value; panics when the entry was skipped.
    #[cfg(all(test, unix))]
    pub(crate) fn into_admitted(self) -> A {
        match self {
            Self::Admit(admitted) => admitted,
            Self::Skipped(_) => panic!("the entry was skipped"),
        }
    }
}

/// Runs `f` with a throwaway tally, for tests that drive a target directly.
#[cfg(all(test, unix))]
pub fn with_tally<R>(f: impl FnOnce(&mut Tally<'_>) -> R) -> R {
    let mut report = ExtractionReport::new();
    let mut progress = crate::NoopProgress;
    let mut tally = Tally {
        report: &mut report,
        options: SinkOptions::default(),
        progress: &mut progress,
    };
    f(&mut tally)
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

    /// Validates a regular file's path, then skips it when the selection leaves
    /// it out, its extension is disallowed or it duplicates an existing path,
    /// or else reserves its size against the quota.
    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<Self::AdmittedFile>>;

    /// Validates a directory entry, or skips it when the selection leaves it
    /// out.
    fn validate_directory(
        &mut self,
        path: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafePath<Self::Parent>>>;

    /// Validates a symlink entry and its target, or skips it when the
    /// selection leaves it out.
    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafeSymlink<Self::Parent>>>;

    /// Validates a hardlink entry for the second pass, or skips it when the
    /// selection leaves it out.
    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<ValidatedHardlink<Self::Parent>>>;

    /// Creates a validated directory.
    fn directory(&mut self, path: &SafePath<Self::Parent>, tally: &mut Tally<'_>) -> Result<()>;

    /// Streams an admitted file from `reader`, capped at the size its quota
    /// permit reserved.
    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        faults: ReadFaults<'_>,
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
        faults: ReadFaults<'_>,
        admitted: Self::AdmittedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        match retained {
            Retained::Bytes(bytes) => self.file(&mut bytes.as_slice(), faults, admitted, tally),
            Retained::Spooled(mut reader) => self.file(&mut reader, faults, admitted, tally),
        }
    }

    /// Creates a validated symlink.
    fn symlink(&mut self, symlink: &SafeSymlink<Self::Parent>, tally: &mut Tally<'_>)
    -> Result<()>;

    /// Settles what only the whole scan decides: the selection's include
    /// patterns that matched no entry. Called once, after the last entry and
    /// before the hardlink pass.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::UnmatchedInclude`] naming every such pattern.
    fn finish_scan(&mut self) -> Result<()>;

    /// Materializes a hardlink in the second pass, once every target exists.
    fn hardlink(
        &mut self,
        link: &SafePath<Self::Parent>,
        target: &HardlinkTarget,
        counted: EntryCount,
        tally: &mut Tally<'_>,
    ) -> Result<()>;
}

/// A validation context whose parent probe the directory walker takes over
/// where the root is pinned: every path validated with it is written through
/// `DirWalker` on `root`, which vets each parent at write time.
///
/// Takes the core and root as separate borrows, so a caller can validate
/// through `&mut` core while the context holds the root.
#[cfg(any(unix, target_os = "wasi"))]
pub(super) fn host_context<'r, V: FsView>(
    core: &ValidatorCore<'_>,
    root: &'r PinnedRoot,
) -> ValidationContext<'r, V, HostParent> {
    core.context::<V>().with_walker(root.backs_parent_probe())
}

/// A validation context for a target without a pinned root: the validator
/// resolves each parent itself.
#[cfg(not(any(unix, target_os = "wasi")))]
pub(super) fn host_context<'r, V: FsView>(
    core: &ValidatorCore<'_>,
    _root: &'r PinnedRoot,
) -> ValidationContext<'r, V, HostParent> {
    core.context::<V>()
}

/// Extraction onto the real filesystem.
pub struct HostTarget<'a> {
    root: PinnedRoot,
    dirs: DirWalker,
    copy_buffer: CopyBuffer,
    core: ValidatorCore<'a>,
    config: &'a SecurityConfig,
}

impl<'a> HostTarget<'a> {
    /// Creates `output_dir` if needed and a target writing into it.
    pub(crate) fn create(output_dir: &Path, config: &'a SecurityConfig) -> Result<Self> {
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

    /// Validates a file's path and applies the selection and the extension
    /// allowlist, leaving quota to the caller.
    pub(super) fn screen_file(
        &self,
        request: FileRequest<'_>,
    ) -> Result<Gated<PendingFile<HostParent>>> {
        let ctx = host_context(&self.core, &self.root);
        self.core.screen_file_path_in(
            request.path,
            request.size,
            request.mode,
            self.root.dest(),
            &PinnedHostFs::new(&self.root),
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
    ) -> Result<Admission<ValidatedFile<HostParent>>> {
        match tally.admission(self.screen_file(request)?, request.path)? {
            Admission::Admit(pending) => self.admit_file(pending).map(Admission::Admit),
            Admission::Skipped(skipped) => Ok(Admission::Skipped(skipped)),
        }
    }

    fn validate_directory(
        &mut self,
        path: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafePath<HostParent>>> {
        let ctx = host_context(&self.core, &self.root);
        let gated = self.core.validate_directory_in(
            path,
            size,
            self.root.dest(),
            &PinnedHostFs::new(&self.root),
            &ctx,
        )?;
        tally.admission(gated, path)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafeSymlink<HostParent>>> {
        let ctx = host_context(&self.core, &self.root);
        let gated = self.core.validate_symlink_in(
            path,
            target,
            size,
            self.root.dest(),
            &PinnedHostFs::new(&self.root),
            &ctx,
        )?;
        tally.admission(gated.map(|validated| validated.symlink), path)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<ValidatedHardlink<HostParent>>> {
        let ctx = host_context(&self.core, &self.root);
        let gated = self.core.validate_hardlink_in(
            path,
            target,
            size,
            self.root.dest(),
            &PinnedHostFs::new(&self.root),
            &ctx,
        )?;
        tally.admission(gated, path)
    }

    fn finish_scan(&mut self) -> Result<()> {
        self.core.finish_selection()
    }

    fn directory(&mut self, path: &SafePath<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        common::create_directory(path, &self.root, tally.report, self.dirs)
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        faults: ReadFaults<'_>,
        admitted: ValidatedFile<HostParent>,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let (path, permit, mode) = admitted.into_parts();
        common::extract_file_with_permit(
            reader,
            faults,
            &path,
            mode,
            permit,
            &self.root,
            tally.report,
            &mut self.copy_buffer,
            self.dirs,
            tally.options,
            tally.progress,
        )
    }

    fn symlink(&mut self, symlink: &SafeSymlink<HostParent>, tally: &mut Tally<'_>) -> Result<()> {
        common::create_symlink(symlink, &self.root, tally.report, self.dirs, tally.options)
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
    ) -> Result<()> {
        self.core
            .require_unambiguous_target(link.as_path(), target.as_path())?;
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
                return match tally.options.existing_files {
                    ExistingFiles::Skip => {
                        common::record_duplicate_skip(tally.report, link.as_path())
                    }
                    ExistingFiles::Refuse => {
                        if self
                            .root
                            .created()
                            .created_here(&link_dir, link_leaf, link.as_path())
                        {
                            common::record_duplicate_skip(tally.report, link.as_path())
                        } else {
                            Err(common::destination_occupied(
                                self.root.dest().as_path(),
                                link.as_path(),
                            ))
                        }
                    }
                    ExistingFiles::Overwrite => {
                        Err(ArchiveError::from(Malformation::DuplicateEntry {
                            path: link.as_path().to_path_buf(),
                        }))
                    }
                };
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };
        self.root.created().note(
            tally.options.existing_files,
            &link_dir,
            link_leaf,
            link.as_path(),
        );
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
            return Err(ArchiveError::from(Malformation::HardlinkTargetNotRegular {
                target: target.as_path().to_path_buf(),
            }));
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
        let resolved = PinnedHostFs::new(&self.root)
            .resolve_link_target(
                link.as_path(),
                target.as_path(),
                LinkBase::Destination,
                dest,
            )
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

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::security::Uncompressed;
    use std::assert_matches;

    fn config() -> SecurityConfig {
        SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true)
    }

    /// A target on a destination whose path is then given to another
    /// directory: `held` is set up in the directory the target holds, `decoy`
    /// in the one now at its path.
    fn replaced_destination<'a>(
        temp: &tempfile::TempDir,
        config: &'a SecurityConfig,
        held: impl FnOnce(&Path),
        decoy: impl FnOnce(&Path),
    ) -> HostTarget<'a> {
        let dest = temp.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        held(&dest);
        let target = HostTarget::create(&dest, config).unwrap();
        std::fs::rename(&dest, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&dest).unwrap();
        decoy(&dest);
        target
    }

    fn size() -> EntrySize {
        EntrySize::new(Uncompressed(0), None)
    }

    fn escaping_link(dest: &Path) {
        std::os::unix::fs::symlink("..", dest.join("up")).unwrap();
    }

    #[test]
    fn a_symlink_is_judged_by_the_held_destination_not_its_path() {
        let config = config();

        let temp = tempfile::TempDir::new().unwrap();
        let mut target = replaced_destination(&temp, &config, escaping_link, |_| {});
        let refused = with_tally(|tally| {
            target.validate_symlink(Path::new("l"), Path::new("up/x"), size(), tally)
        });
        assert_matches!(
            refused,
            Err(ArchiveError::SymlinkEscape { .. }),
            "{refused:?}"
        );

        let temp = tempfile::TempDir::new().unwrap();
        let mut target = replaced_destination(&temp, &config, |_| {}, escaping_link);
        let accepted = with_tally(|tally| {
            target.validate_symlink(Path::new("l"), Path::new("up/x"), size(), tally)
        });
        assert_matches!(accepted, Ok(_), "{accepted:?}");
    }

    #[test]
    fn a_hardlink_is_judged_by_the_held_destination_not_its_path() {
        let config = config();

        let temp = tempfile::TempDir::new().unwrap();
        let mut target = replaced_destination(&temp, &config, escaping_link, |_| {});
        let refused = with_tally(|tally| {
            target.validate_hardlink(Path::new("h"), Path::new("up/x"), size(), tally)
        });
        assert_matches!(
            refused,
            Err(ArchiveError::HardlinkEscape { .. }),
            "{refused:?}"
        );

        let temp = tempfile::TempDir::new().unwrap();
        let mut target = replaced_destination(&temp, &config, |_| {}, escaping_link);
        let accepted = with_tally(|tally| {
            target.validate_hardlink(Path::new("h"), Path::new("up/x"), size(), tally)
        });
        assert_matches!(accepted, Ok(_), "{accepted:?}");
    }

    #[test]
    fn a_hardlink_source_is_opened_through_the_held_destination_not_its_path() {
        use std::io::Read as _;

        let config = config();
        let temp = tempfile::TempDir::new().unwrap();
        let mut target = replaced_destination(
            &temp,
            &config,
            |dest| {
                std::fs::create_dir_all(dest.join("a/b")).unwrap();
                std::os::unix::fs::symlink("a/b", dest.join("s")).unwrap();
                std::fs::write(dest.join("a/f2"), b"held").unwrap();
            },
            |dest| {
                std::fs::create_dir(dest.join("s")).unwrap();
                std::fs::write(dest.join("f2"), b"decoy").unwrap();
            },
        );
        let validated = with_tally(|tally| {
            target.validate_hardlink(Path::new("h"), Path::new("s/../f2"), size(), tally)
        })
        .unwrap()
        .into_admitted();

        let opened = target
            .open_hardlink_target(&validated.link, &validated.target)
            .unwrap();

        let mut content = String::new();
        let mut file = opened.file;
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "held");
    }
}
