//! Extraction into caller-owned storage instead of a directory.

mod callback;
mod memory;

pub use callback::CallbackEntry;
pub use callback::CallbackError;
pub use callback::CallbackSink;
pub use callback::extract_reader_to_callback;
pub use memory::MemoryEntry;
pub use memory::MemoryEntryKind;
pub use memory::MemoryExtractRequest;
pub use memory::MemoryFile;
pub use memory::MemoryLimit;
pub use memory::MemorySink;
pub(crate) use memory::SinkReuse;
pub(crate) use memory::SinkUsage;
pub use memory::extract_reader_to_memory;

use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::DecodeReuse;
use crate::ExistingFiles;
use crate::ExtractionOptions;
use crate::Malformation;
use crate::QuotaResource;
use crate::Result;
use crate::SecurityConfig;
use crate::Staging;
use crate::copy::CopyBuffer;
use crate::copy::copy_bounded;
use crate::formats::common;
use crate::formats::source_fault::ReadFaults;
use crate::formats::target::Admission;
use crate::formats::target::ExtractTarget;
use crate::formats::target::FileRequest;
use crate::formats::target::Tally;
use crate::formats::zip_reuse::Retained;
use crate::security::admitted::EntrySize;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::Containment;
use crate::security::fs_view::FsView as _;
use crate::security::fs_view::LandingLimits;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::ModelRoot as _;
use crate::security::fs_view::Node;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::PathModel;
use crate::security::fs_view::PlaceError;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::fs_view::name_too_long;
use crate::security::hardlink::HardlinkTarget;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::AdmittedSize;
use crate::security::quota::EntryCount;
use crate::security::validator::ValidatorCore;
use crate::types::CheckedLinkTarget;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::Resolved;

/// What a sink extraction honours of [`ExtractionOptions`].
///
/// Atomic extraction renames a directory, which a sink does not have, so the
/// only setting that carries over from path-based options is the
/// occupied-path policy. [`decode_reuse`](Self::decode_reuse) is never carried
/// over: a sink keeps nothing between the structural check and the write unless
/// it is asked to here.
///
/// # Examples
///
/// ```
/// use exarch_core::ExistingFiles;
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SinkOptions;
/// use exarch_core::Staging;
///
/// let options = SinkOptions::default().with_existing_files(ExistingFiles::Overwrite);
/// assert_eq!(options.existing_files, ExistingFiles::Overwrite);
///
/// let atomic = ExtractionOptions::default().with_staging(Staging::Atomic);
/// assert!(SinkOptions::try_from(&atomic).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkOptions {
    /// What to do with an entry whose destination path is already occupied.
    ///
    /// Defaults to [`ExistingFiles::Skip`].
    pub existing_files: ExistingFiles,

    /// Where a ZIP extraction keeps the output its structural check already
    /// decoded, so deflate entries are decoded once instead of twice.
    ///
    /// Defaults to [`DecodeReuse::Off`]: with a callback or a custom sink,
    /// every deflate entry is decoded twice, once by the structural check and
    /// once for the sink. Callback extraction runs in O(buffer) memory in that
    /// default, and any reuse adds to it.
    ///
    /// Measured (2026-11, release build, wall time of
    /// `extract_reader_to_callback`) on a 100 MiB deflate ZIP of ten 10 MiB
    /// members: [`DecodeReuse::Memory`]
    /// at [`ReuseLimit::DEFAULT`](crate::ReuseLimit::DEFAULT) (32 MiB, so three
    /// members are kept) takes about 14% less time than `Off`, and at
    /// [`ReuseLimit::MAX`](crate::ReuseLimit::MAX) (every member kept) about
    /// 47% less. A member above the limit gains nothing: one 40 MiB member
    /// took the same time at the default limit as with `Off`.
    ///
    /// Opting in has these costs:
    ///
    /// - [`DecodeReuse::Memory`] holds up to its
    ///   [`ReuseLimit`](crate::ReuseLimit) on the heap. The limit counts only
    ///   the store; at its peak the process holds the store, the entry being
    ///   delivered and the sink's own copy of it.
    /// - [`DecodeReuse::TempFile`] writes the plaintext of the archive to the
    ///   platform's temporary directory until the extraction ends, which may be
    ///   RAM on a tmpfs.
    /// - An entry above the [`ReuseLimit`](crate::ReuseLimit) is still decoded
    ///   twice.
    ///
    /// [`MemorySink`] extraction through
    /// [`extract_reader_to_memory`] always
    /// reuses in memory within its own limit and ignores this field.
    pub decode_reuse: DecodeReuse,
}

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            existing_files: ExistingFiles::Skip,
            decode_reuse: DecodeReuse::Off,
        }
    }
}

impl SinkOptions {
    /// Sets what happens to an entry whose destination path is occupied.
    #[must_use]
    pub const fn with_existing_files(mut self, existing_files: ExistingFiles) -> Self {
        self.existing_files = existing_files;
        self
    }

    /// Sets where a ZIP extraction keeps the output of its structural check.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::DecodeReuse;
    /// use exarch_core::ReuseLimit;
    /// use exarch_core::SinkOptions;
    ///
    /// let options =
    ///     SinkOptions::default().with_decode_reuse(DecodeReuse::Memory(ReuseLimit::DEFAULT));
    /// assert_eq!(
    ///     options.decode_reuse,
    ///     DecodeReuse::Memory(ReuseLimit::DEFAULT)
    /// );
    /// assert_eq!(SinkOptions::default().decode_reuse, DecodeReuse::Off);
    /// ```
    #[must_use]
    pub const fn with_decode_reuse(mut self, reuse: DecodeReuse) -> Self {
        self.decode_reuse = reuse;
        self
    }
}

impl SinkOptions {
    /// The occupied-path policy of path-based options, for extraction paths
    /// that handle staging themselves.
    pub(crate) const fn existing_files_of(options: &ExtractionOptions) -> Self {
        Self {
            existing_files: options.existing_files,
            decode_reuse: DecodeReuse::Off,
        }
    }
}

impl TryFrom<&ExtractionOptions> for SinkOptions {
    type Error = ArchiveError;

    /// Carries the occupied-path policy over from path-based options.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] for any staging other
    /// than [`Staging::InPlace`], which needs a directory to rename.
    fn try_from(options: &ExtractionOptions) -> Result<Self> {
        match options.staging {
            Staging::InPlace => {}
            Staging::Atomic | Staging::AtomicReplace => {
                return Err(ArchiveError::InvalidConfiguration {
                    setting: crate::ConfigSetting::AtomicExtraction,
                    problem: crate::ConfigProblem::CannotTargetSink,
                });
            }
        }
        Ok(Self {
            existing_files: options.existing_files,
            decode_reuse: DecodeReuse::Off,
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
/// [`SinkExtractRequest`](crate::SinkExtractRequest) runs the same validation
/// pipeline as [`extract_archive`](crate::extract_archive) (quotas, ratio
/// limits, path and link checks, the per-format gates) but hands each entry to
/// an [`EntrySink`], so an archive can be unpacked into memory, an object
/// store or a virtual filesystem without touching the host's.
///
/// # What a sink may rely on
///
/// - Every path is relative, normalized, free of `..`, a root or a prefix, and
///   already resolved through the symlinks of earlier entries: no parent
///   component is a symlink, and two spellings of one name (on hosts that fold
///   case) arrive as one path.
/// - Parent directories are not announced. A file under `a/b` arrives without a
///   `create_directory` for `a` or `b`; create them on demand.
/// - Link targets are validated not to escape the root. Validation uses the
///   sink's [`PathModel`], [`EntrySink::path_model`]. The default, `Host`,
///   follows the platform running the extraction: names fold case only on macOS
///   and Windows, and the Windows component checks run only on Windows, so a
///   sink that writes to a system with another model must not assume the checks
///   hold there. `Portable` applies the strictest rules of every supported
///   platform on every host and suits a sink whose storage is read elsewhere.
/// - Validation assumes an EMPTY namespace: the sink must start empty. Entries
///   the sink already holds are invisible to it.
/// - Occupied paths follow [`SinkOptions`] `existing_files` exactly as the
///   path-based API does: skipped entries are never delivered, and with
///   overwrite a later file replaces an earlier one (a second `create_file` for
///   the same path) and a later symlink replaces an earlier file.
/// - Quotas, ratio limits and declared-size enforcement count the bytes the
///   archive produces, not what the sink stores.
///
/// # Differences from the path-based API
///
/// - Symlinks are delivered on every platform, including hosts where the
///   path-based API refuses to create them: a sink stores a link as data.
/// - A sink failure ends the extraction. When an entry was already delivered,
///   the error is a `PartialExtraction` wrapping [`ArchiveError::Io`].
/// - The model is stricter than the host in a few shapes, and fails closed: a
///   hardlink to a directory is `InvalidArchive` (the host fails in the copy),
///   and that check runs before a duplicate hardlink is skipped; a directory or
///   file entry through a dangling symlink, or over one, is refused.
/// - Under case folding (macOS, Windows, and every host with `Portable`) two
///   spellings of a name are one name, and the path delivered is the spelling
///   stored first.
/// - With `Host` the sink inherits the path-length limits of the platform
///   running the extraction, not its own; `Portable` uses fixed limits. In both
///   models symlink targets and other names are limited, but 8.3 short names
///   and the legacy 260-unit `MAX_PATH` are not modelled.
/// - A path that leaves the root and comes back (a symlink to `..` followed by
///   the root's own name) is refused as an escape, though the host would
///   resolve it inside.
///
/// # Memory used by validation
///
/// The model that validates paths holds every name the archive spells, charged
/// to a budget of `max_file_count * max_path_depth + 1` names (a directory
/// entry and each differently spelled alias of a name cost one name, whatever
/// the entry type); an archive that passes it fails with
/// [`QuotaResource::TreeNodes`]. With the
/// default limits that is 320001 names. Measured on macOS in a release build,
/// 320000 directory entries into a sink that stores nothing peaked at 176 MB
/// resident with 7-byte names and 223 MB with 99-byte names (about 1.6 bytes
/// per name byte on top of about 550 bytes per name), so names of 255 bytes
/// reach roughly 300 MB. [`MemoryLimit`] counts the payload, the path bytes
/// and a fixed 256 bytes per entry, but not this overhead.
///
/// A sink that writes to a real filesystem loses the per-component symlink
/// vetting, `O_NOFOLLOW` and `create_new` defences the path-based API relies
/// on (the pre-existing destination symlink class). Use
/// [`extract_archive`](crate::extract_archive) for that.
///
///
/// The pipeline calls a sink from a single thread, one entry at a time.
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
/// - Under [`ExistingFiles::Overwrite`] a later `create_file` for a path
///   replaces the earlier one, and a hardlink reads the size of the most recent
///   write at its target.
/// - A hardlink is delivered after every other entry. The sink copies the bytes
///   it holds for `target`; the pipeline has already charged the quota for
///   them.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use std::io;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// use exarch_core::AdmittedSize;
/// use exarch_core::ArchiveReader;
/// use exarch_core::CheckedLinkTarget;
/// use exarch_core::EntrySink;
/// use exarch_core::SafePath;
/// use exarch_core::SanitizedMode;
/// use exarch_core::SecurityConfig;
/// use exarch_core::SinkExtractRequest;
/// use exarch_core::SinkOptions;
///
/// #[derive(Default)]
/// struct MapSink(BTreeMap<PathBuf, Vec<u8>>);
///
/// impl EntrySink for MapSink {
///     type File = Vec<u8>;
///
///     fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
///         Ok(())
///     }
///
///     fn create_file(
///         &mut self,
///         _: &SafePath,
///         _: Option<SanitizedMode>,
///         size: AdmittedSize,
///     ) -> io::Result<Vec<u8>> {
///         Ok(Vec::with_capacity(
///             usize::try_from(size.get().min(1 << 16)).unwrap_or(0),
///         ))
///     }
///
///     fn finish_file(&mut self, path: &SafePath, file: Vec<u8>) -> io::Result<()> {
///         self.0.insert(path.as_path().to_path_buf(), file);
///         Ok(())
///     }
///
///     fn create_symlink(&mut self, _: &SafePath, _: CheckedLinkTarget<'_>) -> io::Result<()> {
///         Ok(())
///     }
///
///     fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
///         let bytes = self.0.get(target.as_path()).cloned().unwrap_or_default();
///         self.0.insert(link.as_path().to_path_buf(), bytes);
///         Ok(())
///     }
/// }
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(5);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "docs/hello.txt", &b"hello"[..])?;
/// let archive = builder.into_inner()?;
///
/// let mut sink = MapSink::default();
/// let reader = ArchiveReader::tar(io::Cursor::new(archive), None);
/// let config = SecurityConfig::default();
/// let report = SinkExtractRequest::new(&config)
///     .with_options(SinkOptions::default())
///     .extract(reader, &mut sink)?;
/// assert_eq!(report.files_extracted, 1);
/// assert_eq!(sink.0[Path::new("docs/hello.txt")], b"hello");
/// # Ok(())
/// # }
/// ```
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

    /// Starts a file of exactly `size` bytes, the size the quota tracker
    /// admitted for it.
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
        size: AdmittedSize,
    ) -> io::Result<Self::File>;

    /// Starts a file whose `bytes` are already complete and verified.
    ///
    /// The result is then passed to [`finish_file`](Self::finish_file) like one
    /// from [`create_file`](Self::create_file), and `bytes.len()` equals
    /// `size`. The default writes `bytes` through
    /// [`create_file`](Self::create_file); a sink that keeps its files in
    /// memory can override it to take the buffer without copying it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be started or written.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io;
    ///
    /// use exarch_core::AdmittedSize;
    /// use exarch_core::CheckedLinkTarget;
    /// use exarch_core::EntrySink;
    /// use exarch_core::SafePath;
    /// use exarch_core::SanitizedMode;
    ///
    /// struct VecSink;
    ///
    /// impl EntrySink for VecSink {
    ///     type File = Vec<u8>;
    ///
    ///     fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
    ///         Ok(())
    ///     }
    ///
    ///     fn create_file(
    ///         &mut self,
    ///         _: &SafePath,
    ///         _: Option<SanitizedMode>,
    ///         size: AdmittedSize,
    ///     ) -> io::Result<Vec<u8>> {
    ///         Ok(Vec::with_capacity(
    ///             usize::try_from(size.get().min(1 << 16)).unwrap_or(0),
    ///         ))
    ///     }
    ///
    ///     fn create_file_from(
    ///         &mut self,
    ///         _: &SafePath,
    ///         _: Option<SanitizedMode>,
    ///         _: AdmittedSize,
    ///         bytes: Vec<u8>,
    ///     ) -> io::Result<Vec<u8>> {
    ///         Ok(bytes)
    ///     }
    ///
    ///     fn finish_file(&mut self, _: &SafePath, _: Vec<u8>) -> io::Result<()> {
    ///         Ok(())
    ///     }
    ///
    ///     fn create_symlink(&mut self, _: &SafePath, _: CheckedLinkTarget<'_>) -> io::Result<()> {
    ///         Ok(())
    ///     }
    ///
    ///     fn create_hardlink(&mut self, _: &SafePath, _: &SafePath) -> io::Result<()> {
    ///         Ok(())
    ///     }
    /// }
    /// ```
    fn create_file_from(
        &mut self,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        size: AdmittedSize,
        bytes: Vec<u8>,
    ) -> io::Result<Self::File> {
        let mut file = self.create_file(path, mode, size)?;
        file.write_all(&bytes)?;
        Ok(file)
    }

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
    /// sink may store it as opaque data; [`CheckedLinkTarget::as_path`] gives
    /// the text to store.
    ///
    /// # Errors
    ///
    /// Returns an error if the link cannot be created.
    fn create_symlink(&mut self, link: &SafePath, target: CheckedLinkTarget<'_>) -> io::Result<()>;

    /// Creates `link` with the content of the file at `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the link cannot be created.
    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()>;
}

/// A file admitted and placed in the virtual tree, not yet written.
struct StagedFile {
    path: SafePath,
    mode: Option<SanitizedMode>,
    size: AdmittedSize,
}

/// An [`ExtractTarget`] that validates against an in-memory model of the
/// destination and delivers to an [`EntrySink`].
pub(crate) struct SinkTarget<'a, S: EntrySink> {
    sink: &'a mut S,
    config: &'a SecurityConfig,
    root: VirtualRoot,
    model: PathModel,
    tree: VirtualTree,
    core: ValidatorCore<'a>,
    /// Bytes of every file or materialized hardlink, by resolved path.
    sizes: HashMap<PathBuf, u64>,
    copy_buffer: CopyBuffer,
}

impl<'a, S: EntrySink> SinkTarget<'a, S> {
    pub(crate) fn new(sink: &'a mut S, config: &'a SecurityConfig) -> Self {
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

    /// Validates the placement of an admitted file, or records it as a skipped
    /// duplicate and returns `None`.
    fn stage_file(
        &mut self,
        admitted: ValidatedFile,
        tally: &mut Tally<'_>,
    ) -> Result<Option<StagedFile>> {
        let (path, permit, mode) = admitted.into_parts();
        let size = permit.into_admitted();
        // Overflow guard only, as on the host: the sum is not stored.
        common::checked_add_bytes(tally.report.bytes_written, size.get())?;

        let rel = path.as_path();
        // The tree holds only what this run delivered, so under `Refuse` every
        // occupant is a duplicate of an earlier entry and is skipped, as under
        // `Skip`; an occupant this run did not create cannot exist here.
        match (self.tree.occupant(rel), tally.options.existing_files) {
            (Some(_), ExistingFiles::Skip | ExistingFiles::Refuse) => {
                tally.record_duplicate_skip(rel)?;
                return Ok(None);
            }
            (
                Some(occupant @ (Occupant::Directory | Occupant::Symlink)),
                ExistingFiles::Overwrite,
            ) => {
                return Err(common::occupant_at_dest_error(rel, occupant).into());
            }
            (Some(Occupant::File) | None, ExistingFiles::Overwrite) | (None, _) => {}
        }

        let path = self.place(&path, Node::File)?;
        Ok(Some(StagedFile { path, mode, size }))
    }

    /// Streams `reader` into a new sink file for `staged`, capped at its size.
    fn write_staged<R: Read>(
        &mut self,
        staged: StagedFile,
        reader: &mut R,
        faults: ReadFaults<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let mut file = self
            .sink
            .create_file(&staged.path, staged.mode, staged.size)
            .map_err(sink_error)?;
        let written = copy_bounded(
            reader,
            &mut file,
            &mut self.copy_buffer,
            Some(staged.size.get()),
        )
        .map_err(|error| faults.classify(error))?;
        self.finish_staged(staged.path, file, written, tally)
    }

    fn finish_staged(
        &mut self,
        path: SafePath,
        file: S::File,
        written: u64,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        self.sink.finish_file(&path, file).map_err(sink_error)?;
        self.sizes.insert(path.into_path_buf(), written);
        tally.record_file(written)
    }

    /// Places `node` at `rel`, returning where it landed.
    fn place(&mut self, rel: &SafePath, node: Node) -> Result<SafePath> {
        self.tree
            .project_landing(rel, node, LandingLimits::Enforced)
            .map_err(place_error)
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
        PlaceError::LandingTooLong => ArchiveError::Io(name_too_long()),
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
    type Parent = Resolved;

    fn validate_file(
        &mut self,
        request: FileRequest<'_>,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<ValidatedFile>> {
        let ctx = self.core.context();
        let screen = self.core.screen_file_path_in(
            request.path,
            request.size,
            request.mode,
            &self.root,
            &self.tree,
            &ctx,
        )?;
        match tally.admission(screen, request.path)? {
            Admission::Admit(pending) => {
                let file = self.core.admit_file(pending)?;
                self.check_limits(file.path().as_path(), None)?;
                Ok(Admission::Admit(file))
            }
            Admission::Skipped(skipped) => Ok(Admission::Skipped(skipped)),
        }
    }

    fn validate_directory(
        &mut self,
        path: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafePath>> {
        let ctx = self.core.context();
        let gated = self
            .core
            .validate_directory_in(path, size, &self.root, &self.tree, &ctx)?;
        let admission = tally.admission(gated, path)?;
        if let Admission::Admit(safe_path) = &admission {
            self.check_limits(safe_path.as_path(), None)?;
        }
        Ok(admission)
    }

    fn validate_symlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<SafeSymlink>> {
        let ctx = self.core.context();
        let gated = self
            .core
            .validate_symlink_in(path, target, size, &self.root, &self.tree, &ctx)?;
        let admission = tally.admission(gated.map(|validated| validated.symlink), path)?;
        if let Admission::Admit(symlink) = &admission {
            self.check_limits(symlink.link().as_path(), Some((target, LinkKind::Symlink)))?;
        }
        Ok(admission)
    }

    fn validate_hardlink(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        tally: &mut Tally<'_>,
    ) -> Result<Admission<ValidatedHardlink>> {
        let ctx = self.core.context();
        let gated = self
            .core
            .validate_hardlink_in(path, target, size, &self.root, &self.tree, &ctx)?;
        let admission = tally.admission(gated, path)?;
        if let Admission::Admit(validated) = &admission {
            self.check_limits(
                validated.link.as_path(),
                Some((validated.target.as_path(), LinkKind::Hardlink)),
            )?;
        }
        Ok(admission)
    }

    fn finish_scan(&mut self) -> Result<()> {
        self.core.finish_selection()
    }

    fn directory(&mut self, path: &SafePath, tally: &mut Tally<'_>) -> Result<()> {
        let rel = path.as_path();
        let occupied = self.tree.occupant(rel).is_some();
        let resolved = self.place(path, Node::Dir)?;
        if !occupied && !rel.is_empty() {
            self.sink.create_directory(&resolved).map_err(sink_error)?;
        }
        tally.report.directories_created += 1;
        Ok(())
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        faults: ReadFaults<'_>,
        admitted: ValidatedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let Some(staged) = self.stage_file(admitted, tally)? else {
            return Ok(());
        };
        self.write_staged(staged, reader, faults, tally)
    }

    fn file_retained(
        &mut self,
        retained: Retained<'_>,
        faults: ReadFaults<'_>,
        admitted: ValidatedFile,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        let Some(staged) = self.stage_file(admitted, tally)? else {
            return Ok(());
        };
        match retained {
            Retained::Bytes(bytes) if bytes.len() as u64 == staged.size.get() => {
                let written = bytes.len() as u64;
                let file = self
                    .sink
                    .create_file_from(&staged.path, staged.mode, staged.size, bytes)
                    .map_err(sink_error)?;
                self.finish_staged(staged.path, file, written, tally)
            }
            Retained::Bytes(bytes) => {
                self.write_staged(staged, &mut bytes.as_slice(), faults, tally)
            }
            Retained::Spooled(mut reader) => self.write_staged(staged, &mut reader, faults, tally),
        }
    }

    fn symlink(&mut self, symlink: &SafeSymlink, tally: &mut Tally<'_>) -> Result<()> {
        let link = symlink.link();
        let rel = link.as_path();
        let target = symlink.target_path();
        let occupant = self.tree.occupant(rel);
        match (occupant, tally.options.existing_files) {
            (Some(_), ExistingFiles::Skip | ExistingFiles::Refuse) => {
                return tally.record_duplicate_skip(rel).map(drop);
            }
            (Some(Occupant::Directory), ExistingFiles::Overwrite) => {
                return Err(common::occupant_at_dest_error(rel, Occupant::Directory).into());
            }
            (Some(Occupant::Symlink), ExistingFiles::Overwrite) => {
                // An unchanged link re-points nothing; any other target is
                // refused by the tree.
                let unchanged = self.tree.project_landing(
                    link,
                    Node::Symlink(target.to_path_buf()),
                    LandingLimits::Enforced,
                );
                return match unchanged {
                    Ok(_) => common::record_duplicate_skip(tally.report, rel),
                    Err(PlaceError::Conflict(_)) => {
                        Err(common::occupant_at_dest_error(rel, Occupant::Symlink).into())
                    }
                    Err(error) => Err(place_error(error)),
                };
            }
            (Some(Occupant::File), ExistingFiles::Overwrite) | (None, _) => {}
        }

        let node = Node::Symlink(target.to_path_buf());
        let resolved = match self
            .tree
            .project_landing(link, node.clone(), LandingLimits::Enforced)
        {
            Ok(resolved) => resolved,
            // The tree reports a symlink replacing a file as a conflict but
            // does replace it, as the host does; placing it again finds its
            // own unchanged duplicate and returns the path.
            Err(PlaceError::Conflict(conflict)) if conflict.occupant == Some(Occupant::File) => {
                self.place(link, node)?
            }
            Err(error) => return Err(place_error(error)),
        };
        self.sink
            .create_symlink(&resolved, symlink.checked_target())
            .map_err(sink_error)?;
        tally.report.symlinks_created += 1;
        Ok(())
    }

    fn hardlink(
        &mut self,
        link: &SafePath,
        target: &HardlinkTarget,
        counted: EntryCount,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        self.core
            .require_unambiguous_target(link.as_path(), target.as_path())?;
        let config = self.config;
        let link = SafePath::validate_in(link.as_path(), &self.root, config, &self.tree)?;
        let target = &HardlinkTracker::new().validate_hardlink_in(
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
            return Err(ArchiveError::from(Malformation::HardlinkTargetDirectory {
                target: target.as_path().to_path_buf(),
            }));
        }
        if self.tree.occupant(link.as_path()).is_some() {
            return match tally.options.existing_files {
                ExistingFiles::Skip | ExistingFiles::Refuse => {
                    common::record_duplicate_skip(tally.report, link.as_path())
                }
                ExistingFiles::Overwrite => Err(ArchiveError::from(Malformation::DuplicateEntry {
                    path: link.as_path().to_path_buf(),
                })),
            };
        }

        let resolved_target = self.resolved_target(link.as_path(), target.as_path())?;
        let size = self
            .sizes
            .get(&resolved_target)
            .copied()
            .ok_or_else(|| hardlink_target_missing(target.as_path()))?;
        self.core.charge_hardlink(counted, size).map(drop)?;

        let target_landing =
            SafePath::from_normalized(resolved_target).map_err(ArchiveError::Io)?;
        let resolved = self.place(&link, Node::File)?;
        self.sink
            .create_hardlink(&resolved, &target_landing)
            .map_err(sink_error)?;
        self.sizes.insert(resolved.into_path_buf(), size);

        tally.record_file(size)
    }
}
