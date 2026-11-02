//! Extraction into caller-owned storage instead of a directory.
//!
//! [`extract_to_sink`](crate::extract_to_sink) runs the same validation
//! pipeline as [`extract_archive`](crate::extract_archive) (quotas, ratio
//! limits, path and link checks, the per-format gates) but hands each entry to
//! an [`EntrySink`], so an archive can be unpacked into memory, an object
//! store or a virtual filesystem without touching the host's.
//!
//! # What a sink may rely on
//!
//! - Every path is relative, normalized, free of `..`, a root or a prefix, and
//!   already resolved through the symlinks of earlier entries: no parent
//!   component is a symlink, and two spellings of one name (on hosts that fold
//!   case) arrive as one path.
//! - Parent directories are not announced. A file under `a/b` arrives without a
//!   `create_directory` for `a` or `b`; create them on demand.
//! - Link targets are validated not to escape the root. Validation uses the
//!   sink's [`PathModel`], [`EntrySink::path_model`]. The default, `Host`,
//!   follows the platform running the extraction: names fold case only on macOS
//!   and Windows, and the Windows component checks run only on Windows, so a
//!   sink that writes to a system with another model must not assume the checks
//!   hold there. `Portable` applies the strictest rules of every supported
//!   platform on every host and suits a sink whose storage is read elsewhere.
//! - Validation assumes an EMPTY namespace: the sink must start empty. Entries
//!   the sink already holds are invisible to it.
//! - Duplicates follow [`SinkOptions`] `skip_duplicates` exactly as the
//!   path-based API does: skipped entries are never delivered, and with
//!   overwrite a later file replaces an earlier one (a second `create_file` for
//!   the same path) and a later symlink replaces an earlier file.
//! - Quotas, ratio limits and declared-size enforcement count the bytes the
//!   archive produces, not what the sink stores.
//!
//! # Differences from the path-based API
//!
//! - Symlinks are delivered on every platform, including hosts where the
//!   path-based API refuses to create them: a sink stores a link as data.
//! - A sink failure ends the extraction. When an entry was already delivered,
//!   the error is a `PartialExtraction` wrapping [`ArchiveError::Io`].
//! - The model is stricter than the host in a few shapes, and fails closed: a
//!   hardlink to a directory is `InvalidArchive` (the host fails in the copy),
//!   and that check runs before a duplicate hardlink is skipped; a directory or
//!   file entry through a dangling symlink, or over one, is refused.
//! - Under case folding (macOS, Windows, and every host with `Portable`) two
//!   spellings of a name are one name, and the path delivered is the spelling
//!   stored first.
//! - With `Host` the sink inherits the path-length limits of the platform
//!   running the extraction, not its own; `Portable` uses fixed limits. In both
//!   models symlink targets and other names are limited, but 8.3 short names
//!   and the legacy 260-unit `MAX_PATH` are not modelled.
//! - A path that leaves the root and comes back (a symlink to `..` followed by
//!   the root's own name) is refused as an escape, though the host would
//!   resolve it inside.
//!
//! # Memory used by validation
//!
//! The model that validates paths holds every name the archive spells, charged
//! to a budget of `max_file_count * max_path_depth + 1` names (a directory
//! entry and each differently spelled alias of a name cost one name, whatever
//! the entry type); an archive that passes it fails with
//! [`QuotaResource::TreeNodes`]. With the
//! default limits that is 320001 names. Measured on macOS in a release build,
//! 320000 directory entries into a sink that stores nothing peaked at 176 MB
//! resident with 7-byte names and 223 MB with 99-byte names (about 1.6 bytes
//! per name byte on top of about 550 bytes per name), so names of 255 bytes
//! reach roughly 300 MB. [`MemoryLimit`] counts the payload, the path bytes and
//! a fixed 256 bytes per entry, but not this overhead.
//!
//! A sink that writes to a real filesystem loses the per-component symlink
//! vetting, `O_NOFOLLOW` and `create_new` defences the path-based API relies
//! on (the pre-existing destination symlink class). Use
//! [`extract_archive`](crate::extract_archive) for that.
//!
//! # Examples
//!
//! ```
//! use std::collections::BTreeMap;
//! use std::io;
//! use std::path::Path;
//! use std::path::PathBuf;
//!
//! use exarch_core::ArchiveReader;
//! use exarch_core::EntrySink;
//! use exarch_core::SafePath;
//! use exarch_core::SanitizedMode;
//! use exarch_core::SecurityConfig;
//! use exarch_core::SinkOptions;
//! use exarch_core::extract_to_sink;
//!
//! #[derive(Default)]
//! struct MapSink(BTreeMap<PathBuf, Vec<u8>>);
//!
//! impl EntrySink for MapSink {
//!     type File = Vec<u8>;
//!
//!     fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
//!         Ok(())
//!     }
//!
//!     fn create_file(
//!         &mut self,
//!         _: &SafePath,
//!         _: Option<SanitizedMode>,
//!         size: u64,
//!     ) -> io::Result<Vec<u8>> {
//!         Ok(Vec::with_capacity(
//!             usize::try_from(size.min(1 << 16)).unwrap_or(0),
//!         ))
//!     }
//!
//!     fn finish_file(&mut self, path: &SafePath, file: Vec<u8>) -> io::Result<()> {
//!         self.0.insert(path.as_path().to_path_buf(), file);
//!         Ok(())
//!     }
//!
//!     fn create_symlink(&mut self, _: &SafePath, _: &Path) -> io::Result<()> {
//!         Ok(())
//!     }
//!
//!     fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
//!         let bytes = self.0.get(target.as_path()).cloned().unwrap_or_default();
//!         self.0.insert(link.as_path().to_path_buf(), bytes);
//!         Ok(())
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut builder = tar::Builder::new(Vec::new());
//! let mut header = tar::Header::new_gnu();
//! header.set_size(5);
//! header.set_mode(0o644);
//! builder.append_data(&mut header, "docs/hello.txt", &b"hello"[..])?;
//! let archive = builder.into_inner()?;
//!
//! let mut sink = MapSink::default();
//! let reader = ArchiveReader::tar(io::Cursor::new(archive), None);
//! let report = extract_to_sink(
//!     reader,
//!     &mut sink,
//!     &SecurityConfig::default(),
//!     &SinkOptions::default(),
//! )?;
//! assert_eq!(report.files_extracted, 1);
//! assert_eq!(sink.0[Path::new("docs/hello.txt")], b"hello");
//! # Ok(())
//! # }
//! ```

mod callback;
mod memory;

pub use callback::CallbackSink;
pub use memory::MemoryEntry;
pub use memory::MemoryEntryKind;
pub use memory::MemoryExtractRequest;
pub use memory::MemoryFile;
pub use memory::MemoryLimit;
pub use memory::MemorySink;
pub use memory::extract_reader_to_memory;

use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::QuotaResource;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::copy_with_buffer;
use crate::formats::common;
use crate::formats::target::ExtractTarget;
use crate::formats::target::FileAdmission;
use crate::formats::target::FileRequest;
use crate::formats::target::Tally;
use crate::security::admitted::EntrySize;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::Containment;
use crate::security::fs_view::FsView as _;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::ModelRoot as _;
use crate::security::fs_view::Node;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::PathModel;
use crate::security::fs_view::PlaceError;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::EntryCount;
use crate::security::validator::ValidatorCore;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// What a sink extraction honours of [`ExtractionOptions`].
///
/// Atomic extraction renames a directory, which a sink does not have, so the
/// only setting that carries over is the duplicate policy.
///
/// # Examples
///
/// ```
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SinkOptions;
///
/// let options = SinkOptions::default().with_skip_duplicates(false);
/// assert!(!options.skip_duplicates);
///
/// let atomic = ExtractionOptions::default().with_atomic(true);
/// assert!(SinkOptions::try_from(&atomic).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkOptions {
    /// Skip an entry whose destination path an earlier entry already holds
    /// (the default) instead of failing.
    pub skip_duplicates: bool,
}

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            skip_duplicates: true,
        }
    }
}

impl SinkOptions {
    /// Sets whether a duplicate entry is skipped or fails the extraction.
    #[must_use]
    pub const fn with_skip_duplicates(mut self, skip: bool) -> Self {
        self.skip_duplicates = skip;
        self
    }
}

impl SinkOptions {
    /// The duplicate policy of path-based options, for extraction paths that
    /// handle `atomic` themselves.
    pub(crate) const fn duplicates_of(options: &ExtractionOptions) -> Self {
        Self {
            skip_duplicates: options.skip_duplicates,
        }
    }
}

impl TryFrom<&ExtractionOptions> for SinkOptions {
    type Error = ArchiveError;

    /// Carries the duplicate policy over from path-based options.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for `atomic`, which needs
    /// a directory to rename.
    fn try_from(options: &ExtractionOptions) -> Result<Self> {
        if options.atomic {
            return Err(ArchiveError::InvalidConfiguration {
                reason: "atomic extraction renames a directory and cannot target a sink".into(),
            });
        }
        Ok(Self {
            skip_duplicates: options.skip_duplicates,
        })
    }
}

/// The payload of the [`io::ErrorKind::QuotaExceeded`] error a sink returns
/// when it has no room for an entry.
///
/// Extraction maps it to
/// [`QuotaResource::SinkCapacity`], so a
/// custom sink reports running out of space the same way [`MemorySink`] does,
/// and not as a plain [`ArchiveError::Io`].
///
/// # Examples
///
/// ```
/// use std::io;
///
/// use exarch_core::SinkFull;
///
/// let error = io::Error::new(io::ErrorKind::QuotaExceeded, SinkFull::new(1024));
/// assert_eq!(error.to_string(), "sink is full (1024 bytes)");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkFull {
    max: u64,
}

impl SinkFull {
    /// A full sink whose capacity is `max` bytes.
    #[must_use]
    pub const fn new(max: u64) -> Self {
        Self { max }
    }

    /// The capacity that was exceeded, in bytes.
    #[must_use]
    pub const fn max(&self) -> u64 {
        self.max
    }
}

impl std::fmt::Display for SinkFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sink is full ({} bytes)", self.max)
    }
}

impl std::error::Error for SinkFull {}

/// Receives the validated entries of an archive in extraction order.
///
/// See the [module documentation](self) for what every path and target
/// guarantees. The pipeline calls a sink from a single thread, one entry at a
/// time.
///
/// # Contract
///
/// - A file is delivered as `create_file`, a stream of writes to the returned
///   [`File`](Self::File), then `finish_file`. A `File` that is dropped without
///   `finish_file` is DISCARDED: the pipeline drops it when the entry fails (a
///   forged size, a corrupt stream), so a sink must not publish data from
///   `Drop` or from `write`.
/// - The pipeline never flushes the `File`. `finish_file` must flush any
///   buffering it holds and report a failed flush as an error.
/// - Every `Err` a method returns ends the extraction with [`ArchiveError::Io`]
///   if no entry was delivered yet, and with
///   [`ArchiveError::PartialExtraction`] wrapping it afterwards.
/// - Under overwrite (`skip_duplicates = false`) a later `create_file` for a
///   path replaces the earlier one, and a hardlink reads the size of the most
///   recent write at its target.
/// - A hardlink is delivered after every other entry. The sink copies the bytes
///   it holds for `target`; the pipeline has already charged the quota for
///   them.
pub trait EntrySink {
    /// The writer a file's bytes stream into.
    type File: Write;

    /// The path semantics entries are validated against; the host's by
    /// default.
    ///
    /// A sink whose storage is read on another platform returns
    /// [`PathModel::Portable`].
    fn path_model(&self) -> PathModel {
        PathModel::Host
    }

    /// Creates a directory the archive names explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    fn create_directory(&mut self, path: &SafePath) -> io::Result<()>;

    /// Starts a file of exactly `size` bytes, as the archive declares it.
    ///
    /// `mode` is the permission bits after setuid and setgid are stripped, if
    /// the archive carries any.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be started.
    fn create_file(
        &mut self,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        size: u64,
    ) -> io::Result<Self::File>;

    /// Completes a file after all of its bytes were written and verified.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be stored, including a failed
    /// flush.
    fn finish_file(&mut self, path: &SafePath, file: Self::File) -> io::Result<()>;

    /// Creates a symlink at `link` pointing at `target`, which is stored as
    /// the archive spells it and is validated not to escape the root.
    ///
    /// Entries delivered later are already resolved through this link, so a
    /// sink may store it as opaque data.
    ///
    /// # Errors
    ///
    /// Returns an error if the link cannot be created.
    fn create_symlink(&mut self, link: &SafePath, target: &Path) -> io::Result<()>;

    /// Creates `link` with the content of the file at `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the link cannot be created.
    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()>;
}

/// An [`ExtractTarget`] that validates against an in-memory model of the
/// destination and delivers to an [`EntrySink`].
pub(crate) struct SinkTarget<'a, S: EntrySink> {
    sink: &'a mut S,
    config: &'a SecurityConfig<Validated>,
    root: VirtualRoot,
    model: PathModel,
    tree: VirtualTree,
    core: ValidatorCore<'a>,
    /// Bytes of every file or materialized hardlink, by resolved path.
    sizes: HashMap<PathBuf, u64>,
    copy_buffer: CopyBuffer,
}

impl<'a, S: EntrySink> SinkTarget<'a, S> {
    pub(crate) fn new(sink: &'a mut S, config: &'a SecurityConfig<Validated>) -> Self {
        let root = VirtualRoot::new();
        let model = sink.path_model();
        let tree = VirtualTree::new(
            &root,
            model,
            NodeBudget::from_config(config),
            CollisionRecording::Discard,
        );
        Self {
            sink,
            config,
            root,
            model,
            tree,
            core: ValidatorCore::new(config),
            sizes: HashMap::new(),
            copy_buffer: CopyBuffer::new(),
        }
    }

    /// Places `node` at `rel`, returning where it landed.
    fn place(&mut self, rel: &Path, node: Node) -> Result<SafePath> {
        let resolved = self.tree.place(rel, node).map_err(place_error)?;
        self.landed_within_limits(resolved)
    }

    /// The path an entry landed at, checked against the model's name limits:
    /// the entry's own name was checked before it was resolved through earlier
    /// symlinks, and the path it lands at can be longer.
    fn landed_within_limits(&self, resolved: PathBuf) -> Result<SafePath> {
        self.model
            .check_name_lengths(&resolved)
            .map_err(ArchiveError::Io)?;
        Ok(landed(resolved))
    }

    /// The path model entries are validated against.
    pub(crate) const fn model(&self) -> PathModel {
        self.model
    }

    /// Where a hardlink target ends up once every symlink on it is followed.
    fn resolved_target(&self, link: &Path, target: &Path) -> Result<PathBuf> {
        let canonical = self
            .tree
            .canonicalize(&self.root.as_path().join(target), &self.root)
            .map_err(ArchiveError::Io)?;
        match canonical {
            Containment::Within(path) => path
                .strip_prefix(self.root.as_path())
                .map(Path::to_path_buf)
                .map_err(|_| hardlink_target_missing(target)),
            Containment::Escapes => Err(ArchiveError::HardlinkEscape {
                path: link.to_path_buf(),
            }),
        }
    }
}

fn place_error(error: PlaceError) -> ArchiveError {
    match error {
        PlaceError::Conflict(conflict) => conflict.into_archive_error(),
        PlaceError::Budget(exceeded) => exceeded.into(),
    }
}

/// Maps an error a sink returned, keeping a full sink typed.
fn sink_error(error: io::Error) -> ArchiveError {
    let full = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<SinkFull>())
        .map(SinkFull::max);
    full.map_or_else(
        || ArchiveError::Io(error),
        |max| ArchiveError::QuotaExceeded {
            resource: QuotaResource::SinkCapacity { max },
        },
    )
}

fn landed(resolved: PathBuf) -> SafePath {
    // SAFETY: the tree builds the path from components of entries that passed
    // `SafePath` validation and from nothing else, so it is relative and
    // normalized.
    SafePath::new_unchecked(resolved)
}

impl<S: EntrySink> SinkTarget<'_, S> {
    /// Applies the host's name limits, which the host meets when it writes.
    fn check_limits(&self, path: &Path, link: Option<(&Path, LinkKind)>) -> Result<()> {
        self.model
            .check_name_lengths(path)
            .map_err(ArchiveError::Io)?;
        if let Some((target, kind)) = link {
            self.model
                .check_link_target_length(target, kind)
                .map_err(ArchiveError::Io)?;
        }
        Ok(())
    }
}

impl<S: EntrySink> ExtractTarget for SinkTarget<'_, S> {
    type AdmittedFile = ValidatedFile;

    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        _tally: &mut Tally<'_>,
    ) -> Result<FileAdmission<ValidatedFile>> {
        let ctx = self.core.context();
        let file = self.core.validate_file_in(
            request.path,
            request.size,
            request.mode,
            &self.root,
            &self.tree,
            &ctx,
        )?;
        self.check_limits(request.path, None)?;
        Ok(FileAdmission::Write(file))
    }

    fn validate_directory(&mut self, path: &Path, size: EntrySize) -> Result<SafePath> {
        let ctx = self.core.context();
        let safe_path = self
            .core
            .validate_directory_in(path, size, &self.root, &self.tree, &ctx)?;
        self.check_limits(path, None)?;
        Ok(safe_path)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<SafeSymlink> {
        let ctx = self.core.context();
        let validated = self
            .core
            .validate_symlink_in(path, target, size, &self.root, &self.tree, &ctx)?;
        self.check_limits(path, Some((target, LinkKind::Symlink)))?;
        Ok(validated.symlink)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
    ) -> Result<ValidatedHardlink> {
        let ctx = self.core.context();
        let validated = self
            .core
            .validate_hardlink_in(path, target, size, &self.root, &self.tree, &ctx)?;
        self.check_limits(path, Some((target, LinkKind::Hardlink)))?;
        Ok(validated)
    }

    fn directory(&mut self, path: &SafePath, tally: &mut Tally<'_>) -> Result<()> {
        let rel = path.as_path();
        let occupied = self.tree.occupant(rel).is_some();
        let resolved = self.place(rel, Node::Dir)?;
        if !occupied && !rel.is_empty() {
            self.sink.create_directory(&resolved).map_err(sink_error)?;
        }
        tally.report.directories_created += 1;
        Ok(())
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        admitted: ValidatedFile,
        size: u64,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        // Overflow guard only, as on the host: the sum is not stored.
        common::checked_add_bytes(tally.report.bytes_written, size)?;

        let ValidatedFile { path, mode, .. } = admitted;
        let rel = path.as_path();
        match (self.tree.occupant(rel), tally.options.skip_duplicates) {
            (Some(_), true) => return tally.record_duplicate_skip().map(drop),
            (Some(occupant @ (Occupant::Directory | Occupant::Symlink)), false) => {
                return Err(common::occupant_at_dest_error(rel, occupant).into());
            }
            (Some(Occupant::File) | None, _) => {}
        }

        let resolved = self.place(rel, Node::File)?;
        let mut file = self
            .sink
            .create_file(&resolved, mode, size)
            .map_err(sink_error)?;
        let written = copy_with_buffer(reader, &mut file, &mut self.copy_buffer, Some(size))?;
        self.sink.finish_file(&resolved, file).map_err(sink_error)?;
        self.sizes.insert(resolved.into_path_buf(), written);

        if written > 0 {
            tally.progress.on_bytes_written(written);
        }
        tally.report.files_extracted += 1;
        tally.report.bytes_written =
            common::checked_add_bytes(tally.report.bytes_written, written)?;
        Ok(())
    }

    fn symlink(&mut self, symlink: &SafeSymlink, tally: &mut Tally<'_>) -> Result<()> {
        let rel = symlink.link_path();
        let target = symlink.target_path();
        let occupant = self.tree.occupant(rel);
        match (occupant, tally.options.skip_duplicates) {
            (Some(_), true) => return tally.record_duplicate_skip().map(drop),
            (Some(Occupant::Directory), false) => {
                return Err(common::occupant_at_dest_error(rel, Occupant::Directory).into());
            }
            (Some(Occupant::Symlink), false) => {
                // An unchanged link re-points nothing; any other target is
                // refused by the tree.
                let unchanged = self.tree.place(rel, Node::Symlink(target.to_path_buf()));
                return match unchanged {
                    Ok(_) => common::checked_increment_files_skipped(tally.report),
                    Err(PlaceError::Budget(exceeded)) => Err(exceeded.into()),
                    Err(PlaceError::Conflict(_)) => {
                        Err(common::occupant_at_dest_error(rel, Occupant::Symlink).into())
                    }
                };
            }
            (Some(Occupant::File) | None, _) => {}
        }

        let node = Node::Symlink(target.to_path_buf());
        let resolved = match self.tree.place(rel, node.clone()) {
            Ok(resolved) => self.landed_within_limits(resolved)?,
            // The tree reports a symlink replacing a file as a conflict but
            // does replace it, as the host does; placing it again finds its
            // own unchanged duplicate and returns the path.
            Err(PlaceError::Conflict(conflict)) if conflict.occupant == Some(Occupant::File) => {
                self.place(rel, node)?
            }
            Err(error) => return Err(place_error(error)),
        };
        self.sink
            .create_symlink(&resolved, target)
            .map_err(sink_error)?;
        tally.report.symlinks_created += 1;
        Ok(())
    }

    fn hardlink(
        &mut self,
        link: &SafePath,
        target: &SafePath,
        counted: EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()> {
        let config = self.config;
        let link = SafePath::validate_in(link.as_path(), &self.root, config, &self.tree)?;
        HardlinkTracker::new().validate_hardlink_in(
            &link,
            target.as_path(),
            &self.root,
            config,
            &self.tree,
        )?;

        let full = self.root.as_path().join(target.as_path());
        if !self.tree.exists(&full) {
            return Err(hardlink_target_missing(target.as_path()));
        }
        if self.tree.resolves_to_dir(&full) {
            return Err(ArchiveError::InvalidArchive(format!(
                "hardlink target is a directory: {}",
                target.as_path().display()
            )));
        }
        if self.tree.occupant(link.as_path()).is_some() {
            if tally.options.skip_duplicates {
                common::checked_increment_files_skipped(tally.report)?;
                *hardlink_duplicate_skips = hardlink_duplicate_skips.saturating_add(1);
                return Ok(());
            }
            return Err(ArchiveError::InvalidArchive(format!(
                "duplicate entry: {}",
                link.as_path().display()
            )));
        }

        let resolved_target = self.resolved_target(link.as_path(), target.as_path())?;
        let size = self
            .sizes
            .get(&resolved_target)
            .copied()
            .ok_or_else(|| hardlink_target_missing(target.as_path()))?;
        self.core.charge_hardlink(counted, size).map(drop)?;

        let resolved = self.place(link.as_path(), Node::File)?;
        self.sink
            .create_hardlink(&resolved, &landed(resolved_target))
            .map_err(sink_error)?;
        self.sizes.insert(resolved.into_path_buf(), size);

        tally.report.files_extracted = common::checked_add_count(tally.report.files_extracted, 1)?;
        tally.report.bytes_written = common::checked_add_bytes(tally.report.bytes_written, size)?;
        tally.progress.on_bytes_written(size);
        Ok(())
    }
}
