//! An [`EntrySink`] that keeps the extracted tree in memory.

use std::collections::BTreeMap;
use std::io;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::ArchiveError;
use crate::ArchiveReader;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::closed_enum::closed_enum;
use crate::security::fs_view::PathModel;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::AdmittedSize;
use crate::sink::EntrySink;
use crate::sink::SinkFull;
use crate::sink::SinkOptions;
use crate::types::CheckedLinkTarget;
use crate::types::SafePath;

const DEFAULT_LIMIT_BYTES: u64 = 500 * 1024 * 1024;
const INITIAL_CAPACITY_CAP: u64 = 64 * 1024;

/// The most bytes a [`MemorySink`] accepts, counted as its payload (file data,
/// hardlink copies, symlink targets) plus, for every entry, the bytes of its
/// path and [`MemorySink::ENTRY_OVERHEAD`].
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU64;
///
/// use exarch_core::MemoryLimit;
///
/// assert_eq!(MemoryLimit::new(NonZeroU64::MIN).bytes().get(), 1);
/// assert_eq!(MemoryLimit::DEFAULT.bytes().get(), 500 * 1024 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimit(NonZeroU64);

impl MemoryLimit {
    /// 500 MiB, the default `max_total_size`.
    pub const DEFAULT: Self = Self(match NonZeroU64::new(DEFAULT_LIMIT_BYTES) {
        Some(bytes) => bytes,
        None => NonZeroU64::MIN,
    });

    /// A limit of `bytes`.
    #[must_use]
    pub const fn new(bytes: NonZeroU64) -> Self {
        Self(bytes)
    }

    /// The limit in bytes.
    #[must_use]
    pub const fn bytes(self) -> NonZeroU64 {
        self.0
    }

    /// The limit equal to the config's `max_total_size` (a zero quota becomes
    /// one byte), so raising the extraction quota does not meet a second limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::MemoryLimit;
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(4096));
    /// assert_eq!(MemoryLimit::from_config(&config).bytes().get(), 4096);
    /// ```
    #[must_use]
    pub fn from_config(config: &SecurityConfig) -> Self {
        Self(match config.max_total_size {
            crate::Limit::Bounded(bytes) => bytes,
            crate::Limit::Unbounded => NonZeroU64::MAX,
        })
    }
}

/// The bytes a [`MemorySink`] has charged, readable while the sink is borrowed
/// by an extraction, so the ZIP decode store can share the sink's limit.
#[derive(Debug, Clone, Default)]
pub(crate) struct SinkUsage(Arc<AtomicU64>);

impl SinkUsage {
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn set(&self, bytes: u64) {
        self.0.store(bytes, Ordering::Relaxed);
    }
}

/// What an extraction into a [`MemorySink`] shares with the ZIP decode store:
/// the sink's charged bytes and its limit.
#[derive(Debug)]
pub(crate) struct SinkReuse {
    pub(crate) usage: SinkUsage,
    pub(crate) limit: MemoryLimit,
}

/// An entry held by a [`MemorySink`].
///
/// A [`MemorySink`] stores a hardlink as a copy of the file, so this type has
/// no hardlink variant. A [`CallbackSink`](crate::CallbackSink) delivers a
/// hardlink by reference as a [`CallbackEntry`](crate::CallbackEntry).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryEntry {
    /// A regular file.
    File {
        /// The file's bytes.
        data: Vec<u8>,
        /// The permission bits after setuid and setgid were stripped, if the
        /// archive carries any.
        mode: Option<SanitizedMode>,
    },
    /// A directory the archive names explicitly.
    Directory,
    /// A symbolic link, stored as data.
    Symlink {
        /// The target as the archive spells it, relative to the link.
        target: PathBuf,
    },
}

closed_enum! {
    /// What a [`MemoryEntry`] or a [`CallbackEntry`](crate::CallbackEntry) holds.
    ///
    /// The string form is the one every language binding reports. Only a
    /// [`CallbackEntry`](crate::CallbackEntry) can be a [`Hardlink`](Self::Hardlink).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::MemoryEntry;
    /// use exarch_core::MemoryEntryKind;
    ///
    /// assert_eq!(MemoryEntry::Directory.kind(), MemoryEntryKind::Directory);
    /// assert_eq!(MemoryEntryKind::Symlink.as_str(), "symlink");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum MemoryEntryKind {
        /// A regular file.
        File => "file",
        /// A directory the archive names explicitly.
        Directory => "directory",
        /// A symbolic link, stored as data.
        Symlink => "symlink",
        /// A hard link to an already delivered file, by reference.
        Hardlink => "hardlink",
    }
}

impl MemoryEntry {
    /// What the entry holds.
    #[must_use]
    pub const fn kind(&self) -> MemoryEntryKind {
        match self {
            Self::File { .. } => MemoryEntryKind::File,
            Self::Directory => MemoryEntryKind::Directory,
            Self::Symlink { .. } => MemoryEntryKind::Symlink,
        }
    }

    /// The bytes the entry holds besides its path.
    fn payload_bytes(&self) -> u64 {
        match self {
            Self::File { data, .. } => data.len() as u64,
            Self::Symlink { target } => target.as_os_str().len() as u64,
            Self::Directory => 0,
        }
    }
}

/// How [`extract_reader_to_memory`] validates and stores an archive.
///
/// Every field has a default: the default [`SecurityConfig`] and
/// [`SinkOptions`], the host path model, and a limit equal to the config's
/// `max_total_size` (see [`MemoryLimit::from_config`]).
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU64;
///
/// use exarch_core::MemoryExtractRequest;
/// use exarch_core::MemoryLimit;
/// use exarch_core::PathModel;
///
/// let request = MemoryExtractRequest::default()
///     .with_limit(MemoryLimit::new(NonZeroU64::MIN))
///     .with_path_model(PathModel::Portable);
/// # let _ = request;
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemoryExtractRequest {
    pub(super) config: SecurityConfig,
    pub(super) options: SinkOptions,
    limit: Option<MemoryLimit>,
    pub(super) model: PathModel,
}

impl MemoryExtractRequest {
    /// Validates against `config`.
    #[must_use]
    pub fn with_config(mut self, config: SecurityConfig) -> Self {
        self.config = config;
        self
    }

    /// Applies `options` to the extraction.
    #[must_use]
    pub const fn with_options(mut self, options: SinkOptions) -> Self {
        self.options = options;
        self
    }

    /// Caps the sink at `limit` instead of [`MemoryLimit::from_config`].
    ///
    /// Only [`extract_reader_to_memory`] has a sink to cap;
    /// [`extract_reader_to_callback`](crate::extract_reader_to_callback) keeps
    /// nothing and ignores it.
    #[must_use]
    pub const fn with_limit(mut self, limit: MemoryLimit) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Validates against `model` instead of the host's path rules.
    #[must_use]
    pub const fn with_path_model(mut self, model: PathModel) -> Self {
        self.model = model;
        self
    }
}

/// Extracts the archive in `reader` into a [`MemorySink`].
///
/// Build the reader with [`ArchiveReader::from_bytes`] for bytes in memory, or
/// with [`ArchiveReader::detect`] and friends for a stream. A failure after
/// entries were delivered reports
/// [`PartialWrites::Discarded`](crate::PartialWrites): nothing is written to
/// disk and the entries are dropped with the error.
///
/// # Decode reuse
///
/// A ZIP archive is decoded once: the structural check keeps the output of
/// its compressed entries and extraction replays it. This path always uses
/// in-memory reuse, whatever `config.decode_reuse` says, and the kept bytes
/// together with what the sink holds stay within the smaller of the sink's
/// memory limit and `max_decoder_memory`.
///
/// # Errors
///
/// Returns the errors of
/// [`SinkExtractRequest::extract`](crate::SinkExtractRequest::extract).
///
/// # Examples
///
/// ```
/// use std::assert_matches;
///
/// use exarch_core::ArchiveReader;
/// use exarch_core::MemoryEntry;
/// use exarch_core::MemoryExtractRequest;
/// use exarch_core::NoopProgress;
/// use exarch_core::extract_reader_to_memory;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(2);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "a.txt", &b"hi"[..])?;
///
/// let reader = ArchiveReader::from_bytes(builder.into_inner()?, None)?;
/// let (report, sink) =
///     extract_reader_to_memory(reader, &MemoryExtractRequest::default(), &mut NoopProgress)?;
/// assert_eq!(report.files_extracted, 1);
/// let entries = sink.into_entries();
/// assert_matches!(entries.values().next(), Some(MemoryEntry::File { .. }));
/// # Ok(())
/// # }
/// ```
pub fn extract_reader_to_memory(
    reader: ArchiveReader<'_>,
    request: &MemoryExtractRequest,
    progress: &mut dyn ProgressCallback,
) -> Result<(ExtractionReport, MemorySink)> {
    let limit = request
        .limit
        .unwrap_or_else(|| MemoryLimit::from_config(&request.config));
    let mut sink = MemorySink::new(limit).with_path_model(request.model);
    let reuse = SinkReuse {
        usage: sink.usage(),
        limit,
    };
    let report = crate::api::extract_to_sink_reusing(
        reader,
        &mut sink,
        &request.config,
        request.options,
        progress,
        Some(reuse),
    )
    .map_err(ArchiveError::discarded)?;
    Ok((report, sink))
}

/// The writer of a file being stored by a [`MemorySink`].
///
/// Nothing is published until `finish_file`; dropping it discards the bytes.
#[derive(Debug)]
pub struct MemoryFile {
    data: Vec<u8>,
    mode: Option<SanitizedMode>,
}

impl MemoryFile {
    /// A writer that holds `data` already, for a file received whole.
    pub(crate) const fn from_vec(data: Vec<u8>, mode: Option<SanitizedMode>) -> Self {
        Self { data, mode }
    }

    /// A writer for a file of `size` bytes, pre-allocating at most 64 KiB so a
    /// forged size cannot reserve memory before any byte arrives.
    pub(crate) fn with_size(size: u64, mode: Option<SanitizedMode>) -> Self {
        let capacity = usize::try_from(size.min(INITIAL_CAPACITY_CAP)).unwrap_or(0);
        Self {
            data: Vec::with_capacity(capacity),
            mode,
        }
    }

    /// The completed file, with its buffer shrunk to the bytes received.
    pub(crate) fn into_entry(self) -> MemoryEntry {
        let Self { mut data, mode } = self;
        data.shrink_to_fit();
        MemoryEntry::File { data, mode }
    }
}

impl Write for MemoryFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An [`EntrySink`] that keeps the extracted tree in memory.
///
/// The [`MemoryLimit`] counts, for every entry (directories included), the
/// bytes of its path plus [`ENTRY_OVERHEAD`](Self::ENTRY_OVERHEAD), and for
/// files, hardlink copies and symlinks their payload. A flood of directory
/// entries with long names therefore fills the sink instead of growing it
/// without bound. The overhead of the model that validates the archive is
/// bounded separately by the node budget and is not counted. While a file is
/// written its buffer may be up to twice the bytes received; it is shrunk when
/// the file is stored.
///
/// # Examples
///
/// ```
/// use std::assert_matches;
/// use std::io;
/// use std::path::Path;
///
/// use exarch_core::ArchiveReader;
/// use exarch_core::SinkExtractRequest;
/// use exarch_core::SinkOptions;
/// use exarch_core::MemoryEntry;
/// use exarch_core::MemorySink;
/// use exarch_core::SecurityConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(5);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "docs/hello.txt", &b"hello"[..])?;
/// let archive = builder.into_inner()?;
///
/// let mut sink = MemorySink::default();
/// let reader = ArchiveReader::tar(io::Cursor::new(archive), None);
/// let config = SecurityConfig::default();
/// SinkExtractRequest::new(&config)
///     .with_options(SinkOptions::default())
///     .extract(reader, &mut sink)?;
/// assert_matches!(
///     sink.get(Path::new("docs/hello.txt")),
///     Some(MemoryEntry::File { data, .. }) if data == b"hello"
/// );
/// assert_eq!(
///     sink.stored_bytes(),
///     MemorySink::ENTRY_OVERHEAD + "docs/hello.txt".len() as u64 + 5
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MemorySink {
    limit: MemoryLimit,
    path_model: PathModel,
    stored: u64,
    usage: SinkUsage,
    entries: BTreeMap<PathBuf, MemoryEntry>,
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new(MemoryLimit::DEFAULT)
    }
}

impl MemorySink {
    /// Bytes charged to the limit for every entry on top of its path and
    /// payload, covering the map node and the entry itself.
    pub const ENTRY_OVERHEAD: u64 = 256;

    /// An empty sink that accepts at most `limit` bytes.
    #[must_use]
    pub fn new(limit: MemoryLimit) -> Self {
        Self {
            limit,
            path_model: PathModel::Host,
            stored: 0,
            usage: SinkUsage(Arc::new(AtomicU64::new(0))),
            entries: BTreeMap::new(),
        }
    }

    /// Validates against `path_model` instead of the host's rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::EntrySink;
    /// use exarch_core::MemorySink;
    /// use exarch_core::PathModel;
    ///
    /// let sink = MemorySink::default().with_path_model(PathModel::Portable);
    /// assert_eq!(sink.path_model(), PathModel::Portable);
    /// ```
    #[must_use]
    pub const fn with_path_model(mut self, path_model: PathModel) -> Self {
        self.path_model = path_model;
        self
    }

    /// The limit on charged bytes.
    #[must_use]
    pub const fn limit(&self) -> MemoryLimit {
        self.limit
    }

    /// The bytes charged to the limit now: payload, path bytes and
    /// [`ENTRY_OVERHEAD`](Self::ENTRY_OVERHEAD) per entry.
    #[must_use]
    pub const fn stored_bytes(&self) -> u64 {
        self.stored
    }

    /// The entry at `path`, spelled as it was delivered.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&MemoryEntry> {
        self.entries.get(path)
    }

    /// Every entry in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&Path, &MemoryEntry)> {
        self.entries
            .iter()
            .map(|(path, entry)| (path.as_path(), entry))
    }

    /// Consumes the sink into its entries.
    #[must_use]
    pub fn into_entries(self) -> BTreeMap<PathBuf, MemoryEntry> {
        self.entries
    }

    fn full(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::QuotaExceeded,
            SinkFull::new(self.limit.bytes().get()),
        )
    }

    pub(crate) fn usage(&self) -> SinkUsage {
        self.usage.clone()
    }

    pub(crate) fn charge_of(path: &Path, payload: u64) -> u64 {
        Self::ENTRY_OVERHEAD
            .saturating_add(path.as_os_str().len() as u64)
            .saturating_add(payload)
    }

    fn held_at(&self, path: &Path) -> u64 {
        self.entries
            .get(path)
            .map_or_default(|entry| Self::charge_of(path, entry.payload_bytes()))
    }

    /// The total charge after replacing the entry at `path` by one with
    /// `payload`, or the full error if that passes the limit.
    fn charged_with(&self, path: &Path, payload: u64) -> io::Result<u64> {
        self.stored
            .saturating_sub(self.held_at(path))
            .checked_add(Self::charge_of(path, payload))
            .filter(|total| *total <= self.limit.bytes().get())
            .ok_or_else(|| self.full())
    }

    /// Stores `entry` at `path`, replacing the entry there, unless the charge
    /// would pass the limit.
    fn store(&mut self, path: &SafePath, entry: MemoryEntry) -> io::Result<()> {
        let key = path.as_path();
        self.stored = self.charged_with(key, entry.payload_bytes())?;
        self.usage.set(self.stored);
        self.entries.insert(key.to_path_buf(), entry);
        Ok(())
    }

    /// Drops the entry at `path` to make room for a file of `size` bytes, or
    /// refuses a file that would pass the limit.
    fn reserve_file(&mut self, path: &SafePath, size: u64) -> io::Result<()> {
        self.charged_with(path.as_path(), size)?;
        self.stored = self.stored.saturating_sub(self.held_at(path.as_path()));
        self.usage.set(self.stored);
        self.entries.remove(path.as_path());
        Ok(())
    }
}

impl EntrySink for MemorySink {
    type File = MemoryFile;

    fn path_model(&self) -> PathModel {
        self.path_model
    }

    fn create_directory(&mut self, path: &SafePath) -> io::Result<()> {
        self.store(path, MemoryEntry::Directory)
    }

    fn create_file(
        &mut self,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        size: AdmittedSize,
    ) -> io::Result<MemoryFile> {
        self.reserve_file(path, size.get())?;
        Ok(MemoryFile::with_size(size.get(), mode))
    }

    fn create_file_from(
        &mut self,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        size: AdmittedSize,
        bytes: Vec<u8>,
    ) -> io::Result<MemoryFile> {
        self.reserve_file(path, size.get())?;
        Ok(MemoryFile::from_vec(bytes, mode))
    }

    fn finish_file(&mut self, path: &SafePath, file: MemoryFile) -> io::Result<()> {
        self.store(path, file.into_entry())
    }

    fn create_symlink(&mut self, link: &SafePath, target: CheckedLinkTarget<'_>) -> io::Result<()> {
        self.store(
            link,
            MemoryEntry::Symlink {
                target: target.as_path().to_path_buf(),
            },
        )
    }

    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
        let Some(MemoryEntry::File { data, mode }) = self.entries.get(target.as_path()) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "hardlink target is not a file",
            ));
        };
        self.charged_with(link.as_path(), data.len() as u64)?;
        let copy = MemoryEntry::File {
            data: data.clone(),
            mode: *mode,
        };
        self.store(link, copy)
    }
}
