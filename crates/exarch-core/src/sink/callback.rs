//! An [`EntrySink`] that hands every verified entry to a closure.

use std::error::Error;
use std::fmt;
use std::io;

use crate::ArchiveError;
use crate::ArchiveReader;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::security::fs_view::PathModel;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::AdmittedSize;
use crate::sink::EntrySink;
use crate::sink::MemoryEntry;
use crate::sink::MemoryEntryKind;
use crate::sink::MemoryExtractRequest;
use crate::sink::MemoryFile;
use crate::types::CheckedLinkTarget;
use crate::types::SafePath;

/// An entry delivered by a [`CallbackSink`].
///
/// Everything a [`MemorySink`](crate::MemorySink) can hold is
/// [`Stored`](Self::Stored); a hardlink is delivered by reference instead,
/// because the sink keeps no bytes to copy.
///
/// # Examples
///
/// ```
/// use exarch_core::CallbackEntry;
/// use exarch_core::MemoryEntry;
/// use exarch_core::MemoryEntryKind;
///
/// let entry = CallbackEntry::from(MemoryEntry::Directory);
/// assert_eq!(entry.kind(), MemoryEntryKind::Directory);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallbackEntry {
    /// A file, directory or symlink, as a [`MemorySink`](crate::MemorySink)
    /// would store it.
    Stored(MemoryEntry),
    /// A hard link to an entry that was already delivered, by reference.
    Hardlink {
        /// The validated, root-relative path of an already delivered entry: a
        /// file, or an earlier hardlink (a chain is delivered link by link).
        target: SafePath,
    },
}

impl CallbackEntry {
    /// What the entry holds.
    #[must_use]
    pub const fn kind(&self) -> MemoryEntryKind {
        match self {
            Self::Stored(entry) => entry.kind(),
            Self::Hardlink { .. } => MemoryEntryKind::Hardlink,
        }
    }
}

impl From<MemoryEntry> for CallbackEntry {
    fn from(entry: MemoryEntry) -> Self {
        Self::Stored(entry)
    }
}

/// An [`EntrySink`] that delivers each entry to a closure as it is verified.
///
/// The closure receives the entry's validated path and a [`CallbackEntry`]. A
/// file is delivered whole, after all of its bytes were written and the stream
/// delivered exactly the size the archive declares. The memory held at any
/// moment is one file, bounded by the configuration's `max_file_size`; the sink
/// keeps nothing after delivery.
///
/// # Entries are provisional
///
/// An entry is delivered as soon as it is verified, before the rest of the
/// archive is read. A later failure (a corrupt or refused member further on)
/// ends the extraction after earlier entries were delivered, so treat what the
/// closure received as final only once the extraction returned `Ok`. A
/// stream-level checksum is checked last: the gzip trailer CRC of a `.tar.gz`
/// is verified after the end-of-archive marker, so a corrupt compressed stream
/// ends the extraction with an error only after its entries were delivered.
///
/// An error from the closure ends the extraction like any other sink error
/// (see [`EntrySink`]).
///
/// # What `target` means
///
/// - A [`MemoryEntry::Symlink`] target is spelled as the archive stores it and
///   is relative to the directory of the link.
/// - A [`CallbackEntry::Hardlink`] target is the validated, root-relative,
///   resolved [`SafePath`] of an entry that was already delivered: a file, or
///   an earlier hardlink, so a chain of links is delivered link by link. The
///   sink holds no bytes, so the closure resolves the reference against what it
///   kept.
///
/// # Delivery rules
///
/// - Under overwrite (`skip_duplicates = false`) one path can be delivered more
///   than once, and a hardlink refers to the most recent delivery of its
///   target.
/// - Implicit parent directories are not delivered; only directories the
///   archive names are.
/// - A hardlink is delivered after every other entry. Its bytes stay charged to
///   the extraction quota although they are not copied.
///
/// # Examples
///
/// ```
/// use std::io;
///
/// use exarch_core::ArchiveReader;
/// use exarch_core::CallbackEntry;
/// use exarch_core::CallbackSink;
/// use exarch_core::MemoryEntry;
/// use exarch_core::SecurityConfig;
/// use exarch_core::SinkOptions;
/// use exarch_core::extract_to_sink;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(5);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "docs/hello.txt", &b"hello"[..])?;
/// let archive = builder.into_inner()?;
///
/// let mut seen = Vec::new();
/// let mut sink = CallbackSink::new(|path, entry| {
///     if let CallbackEntry::Stored(MemoryEntry::File { data, .. }) = entry {
///         seen.push((path.as_path().to_path_buf(), data));
///     }
///     Ok(())
/// });
/// let reader = ArchiveReader::tar(io::Cursor::new(archive), None);
/// extract_to_sink(
///     reader,
///     &mut sink,
///     &SecurityConfig::default(),
///     &SinkOptions::default(),
/// )?;
/// assert_eq!(seen.len(), 1);
/// assert_eq!(seen[0].1, b"hello");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CallbackSink<F> {
    callback: F,
    path_model: PathModel,
}

impl<F> CallbackSink<F>
where
    F: FnMut(&SafePath, CallbackEntry) -> io::Result<()>,
{
    /// A sink that calls `callback` for every entry, validating against the
    /// host's path rules.
    #[must_use]
    pub const fn new(callback: F) -> Self {
        Self {
            callback,
            path_model: PathModel::Host,
        }
    }

    /// Validates against `path_model` instead of the host's rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io;
    ///
    /// use exarch_core::CallbackSink;
    /// use exarch_core::EntrySink as _;
    /// use exarch_core::PathModel;
    ///
    /// let sink = CallbackSink::new(|_, _| Ok(())).with_path_model(PathModel::Portable);
    /// assert_eq!(sink.path_model(), PathModel::Portable);
    /// ```
    #[must_use]
    pub const fn with_path_model(mut self, path_model: PathModel) -> Self {
        self.path_model = path_model;
        self
    }
}

impl<F> EntrySink for CallbackSink<F>
where
    F: FnMut(&SafePath, CallbackEntry) -> io::Result<()>,
{
    type File = MemoryFile;

    fn path_model(&self) -> PathModel {
        self.path_model
    }

    fn create_directory(&mut self, path: &SafePath) -> io::Result<()> {
        (self.callback)(path, MemoryEntry::Directory.into())
    }

    fn create_file(
        &mut self,
        _path: &SafePath,
        mode: Option<SanitizedMode>,
        size: AdmittedSize,
    ) -> io::Result<MemoryFile> {
        Ok(MemoryFile::with_size(size.get(), mode))
    }

    fn finish_file(&mut self, path: &SafePath, file: MemoryFile) -> io::Result<()> {
        (self.callback)(path, file.into_entry().into())
    }

    fn create_symlink(&mut self, link: &SafePath, target: CheckedLinkTarget<'_>) -> io::Result<()> {
        (self.callback)(
            link,
            MemoryEntry::Symlink {
                target: target.as_path().to_path_buf(),
            }
            .into(),
        )
    }

    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
        (self.callback)(
            link,
            CallbackEntry::Hardlink {
                target: target.clone(),
            },
        )
    }
}

/// Why [`extract_reader_to_callback`] failed.
///
/// The first error the callback returned is kept as `E`, so the caller keeps
/// its own error type instead of recovering it from a side slot.
///
/// # Examples
///
/// ```
/// use std::error::Error as _;
///
/// use exarch_core::CallbackError;
///
/// let err = CallbackError::Callback(std::io::Error::other("stop"));
/// assert_eq!(err.to_string(), "entry callback failed");
/// assert_eq!(
///     err.source().map(ToString::to_string).as_deref(),
///     Some("stop")
/// );
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum CallbackError<E> {
    /// The callback returned this error for an entry, which ended the
    /// extraction. It takes precedence over the archive error the aborted
    /// extraction reports.
    Callback(E),
    /// The archive was refused or could not be read.
    Archive(ArchiveError),
}

/// `Callback` names the failure and chains to the callback's error through
/// `source()`; `Archive` is transparent, so an error chain shows each message
/// once.
impl<E> fmt::Display for CallbackError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Callback(_) => f.write_str("entry callback failed"),
            Self::Archive(err) => err.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for CallbackError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Callback(err) => Some(err),
            Self::Archive(err) => err.source(),
        }
    }
}

impl<E> From<ArchiveError> for CallbackError<E> {
    fn from(err: ArchiveError) -> Self {
        Self::Archive(err)
    }
}

/// Extracts the archive in `reader`, handing every verified entry to
/// `on_entry`.
///
/// Validates with the config, options and path model of `request`; its memory
/// limit is ignored, since nothing is kept. Entries are provisional and
/// delivered as described at [`CallbackSink`]. The first error `on_entry`
/// returns ends the extraction and is returned as
/// [`CallbackError::Callback`], ahead of any archive error.
///
/// # Errors
///
/// [`CallbackError::Callback`] with the first error of `on_entry`, else
/// [`CallbackError::Archive`] with the errors of
/// [`extract_to_sink_with_progress`](crate::extract_to_sink_with_progress).
///
/// # Examples
///
/// ```
/// use std::assert_matches;
///
/// use exarch_core::ArchiveReader;
/// use exarch_core::CallbackError;
/// use exarch_core::MemoryExtractRequest;
/// use exarch_core::NoopProgress;
/// use exarch_core::extract_reader_to_callback;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(2);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "a.txt", &b"hi"[..])?;
/// let archive = builder.into_inner()?;
///
/// let mut paths = Vec::new();
/// let reader = ArchiveReader::from_bytes(archive.clone(), None)?;
/// extract_reader_to_callback(
///     reader,
///     &MemoryExtractRequest::default(),
///     |path, _entry| {
///         paths.push(path.as_path().to_path_buf());
///         Ok::<(), std::io::Error>(())
///     },
///     &mut NoopProgress,
/// )?;
/// assert_eq!(paths.len(), 1);
///
/// let reader = ArchiveReader::from_bytes(archive, None)?;
/// let failed = extract_reader_to_callback(
///     reader,
///     &MemoryExtractRequest::default(),
///     |_, _| Err(std::io::Error::other("stop")),
///     &mut NoopProgress,
/// );
/// assert_matches!(failed, Err(CallbackError::Callback(err)) if err.to_string() == "stop");
/// # Ok(())
/// # }
/// ```
pub fn extract_reader_to_callback<F, E>(
    reader: ArchiveReader<'_>,
    request: &MemoryExtractRequest,
    mut on_entry: F,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport, CallbackError<E>>
where
    F: FnMut(&SafePath, CallbackEntry) -> Result<(), E>,
{
    let mut failure = None;
    let mut sink = CallbackSink::new(|path: &SafePath, entry| {
        on_entry(path, entry).map_err(|err| {
            failure.get_or_insert(err);
            io::Error::other("entry callback failed")
        })
    })
    .with_path_model(request.model);
    let result = crate::extract_to_sink_with_progress(
        reader,
        &mut sink,
        &request.config,
        &request.options,
        progress,
    );
    match (failure, result) {
        (Some(err), _) => Err(CallbackError::Callback(err)),
        (None, Ok(report)) => Ok(report),
        (None, Err(err)) => Err(CallbackError::Archive(err)),
    }
}
