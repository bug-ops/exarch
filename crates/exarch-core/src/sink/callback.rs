//! An [`EntrySink`] that hands every verified entry to a closure.

use std::io;
use std::path::Path;

use crate::security::fs_view::PathModel;
use crate::security::permissions::SanitizedMode;
use crate::sink::EntrySink;
use crate::sink::MemoryEntry;
use crate::sink::MemoryFile;
use crate::types::SafePath;

/// An [`EntrySink`] that delivers each entry to a closure as it is verified.
///
/// The closure receives the entry's validated path and a [`MemoryEntry`]. A
/// file is delivered whole, after all of its bytes were written and checked
/// against the declared size, so the closure never sees data from a forged or
/// corrupt entry. The memory held at any moment is one file, bounded by the
/// configuration's `max_file_size`; the sink keeps nothing after delivery.
///
/// An error from the closure ends the extraction like any other sink error
/// (see [`EntrySink`]).
///
/// # What `target` means
///
/// - A [`MemoryEntry::Symlink`] target is spelled as the archive stores it and
///   is relative to the directory of the link.
/// - A [`MemoryEntry::Hardlink`] target is the root-relative, resolved path of
///   a file that was already delivered. The sink holds no bytes, so the closure
///   resolves the reference against what it kept.
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
///     if let MemoryEntry::File { data, .. } = entry {
///         seen.push((path.as_path().to_path_buf(), data));
///     }
///     Ok::<(), io::Error>(())
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
    F: FnMut(&SafePath, MemoryEntry) -> io::Result<()>,
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
    /// let sink =
    ///     CallbackSink::new(|_, _| Ok::<(), io::Error>(())).with_path_model(PathModel::Portable);
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
    F: FnMut(&SafePath, MemoryEntry) -> io::Result<()>,
{
    type File = MemoryFile;

    fn path_model(&self) -> PathModel {
        self.path_model
    }

    fn create_directory(&mut self, path: &SafePath) -> io::Result<()> {
        (self.callback)(path, MemoryEntry::Directory)
    }

    fn create_file(
        &mut self,
        _path: &SafePath,
        mode: Option<SanitizedMode>,
        size: u64,
    ) -> io::Result<MemoryFile> {
        Ok(MemoryFile::with_size(size, mode))
    }

    fn finish_file(&mut self, path: &SafePath, file: MemoryFile) -> io::Result<()> {
        (self.callback)(path, file.into_entry())
    }

    fn create_symlink(&mut self, link: &SafePath, target: &Path) -> io::Result<()> {
        (self.callback)(
            link,
            MemoryEntry::Symlink {
                target: target.to_path_buf(),
            },
        )
    }

    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
        (self.callback)(
            link,
            MemoryEntry::Hardlink {
                target: target.as_path().to_path_buf(),
            },
        )
    }
}
