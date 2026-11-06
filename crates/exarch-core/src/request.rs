//! Request values: one type per operation, optional inputs as setters.
//!
//! Every operation (extract, list, verify, extract into a sink, create) is
//! described by a request that holds the configuration it runs under, the
//! options of that operation and an optional [`ProgressCallback`]. A terminal
//! method runs it. Adding an optional input to an operation is a setter on its
//! request, not another function per combination.
//!
//! The plain functions ([`extract_archive`](crate::extract_archive),
//! [`list_archive`](crate::list_archive), ...) remain for the common case; they
//! are requests with the defaults.

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveReader;
use crate::ArchiveWriter;
use crate::DecodeReuse;
use crate::EntrySink;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ListOptions;
use crate::NoopProgress;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::VerificationOptions;
use crate::api::extract_to_sink_reusing;
use crate::api::extract_validated;
use crate::api::resolve_output_format;
use crate::closed_enum::closed_enum;
use crate::creation::CreationConfig;
use crate::creation::CreationReport;
use crate::creation::progress::check_cancelled;
use crate::creation::staged::StagedOutput;
use crate::creation::tar::write_tar;
use crate::creation::zip::warn_on_extraction_ratio;
use crate::creation::zip::write_zip;
use crate::formats::detect::CreatableFormat;
use crate::formats::detect::CreationFamily;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;
use crate::inspection::list::ListPass;
use crate::listed::ListedArchive;
use crate::staging::extract_staged;

/// The optional progress callback of a request; a missing one is a no-op.
struct OptionalProgress<'a>(Option<&'a mut dyn ProgressCallback>);

impl std::fmt::Debug for OptionalProgress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "Some(..)" } else { "None" })
    }
}

impl OptionalProgress<'_> {
    fn run<R>(self, operation: impl FnOnce(&mut dyn ProgressCallback) -> R) -> R {
        match self.0 {
            Some(progress) => operation(progress),
            None => operation(&mut NoopProgress),
        }
    }
}

/// The configuration, options and optional progress callback that every
/// request carries; the public request types wrap it with their own setters and
/// terminal methods.
#[derive(Debug)]
struct Carrier<'a, C, O> {
    config: &'a C,
    options: O,
    progress: OptionalProgress<'a>,
}

impl<'a, C, O> Carrier<'a, C, O> {
    const fn new(config: &'a C, options: O) -> Self {
        Self {
            config,
            options,
            progress: OptionalProgress(None),
        }
    }

    fn with_options(mut self, options: O) -> Self {
        self.options = options;
        self
    }

    fn with_progress(mut self, progress: &'a mut dyn ProgressCallback) -> Self {
        self.progress = OptionalProgress(Some(progress));
        self
    }

    fn run<R>(self, operation: impl FnOnce(&'a C, O, &mut dyn ProgressCallback) -> R) -> R {
        let Self {
            config,
            options,
            progress,
        } = self;
        progress.run(|progress| operation(config, options, progress))
    }
}

/// Extracts an archive into a directory.
///
/// Holds the [`SecurityConfig`] the extraction runs under, the
/// [`ExtractionOptions`] and an optional [`ProgressCallback`]. Every entry
/// passes the validation pipeline before it is written.
///
/// # Errors
///
/// [`extract`](Self::extract) returns an error if:
/// - the archive cannot be opened
/// - the archive format is unsupported
/// - security validation fails
/// - an I/O operation fails
/// - the atomic staging directory cannot be created or renamed into place
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractRequest;
/// use exarch_core::ExtractionOptions;
/// use exarch_core::NoopProgress;
/// use exarch_core::SecurityConfig;
/// use exarch_core::Staging;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let mut progress = NoopProgress;
/// let report = ExtractRequest::new(&config)
///     .with_options(ExtractionOptions::default().with_staging(Staging::Atomic))
///     .with_progress(&mut progress)
///     .extract("archive.tar.gz", "/tmp/output")?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ExtractRequest<'a>(Carrier<'a, SecurityConfig, ExtractionOptions>);

impl<'a> ExtractRequest<'a> {
    /// An extraction under `config` with default options and no progress
    /// callback.
    #[must_use]
    pub fn new(config: &'a SecurityConfig) -> Self {
        Self(Carrier::new(config, ExtractionOptions::default()))
    }

    /// Sets the extraction options.
    #[must_use]
    pub fn with_options(self, options: ExtractionOptions) -> Self {
        Self(self.0.with_options(options))
    }

    /// Reports progress to `progress`.
    #[must_use]
    pub fn with_progress(self, progress: &'a mut dyn ProgressCallback) -> Self {
        Self(self.0.with_progress(progress))
    }

    /// Extracts `archive` into `output_dir`; the format is detected.
    ///
    /// # Errors
    ///
    /// See [`ExtractRequest`].
    pub fn extract(
        self,
        archive: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
    ) -> Result<ExtractionReport> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            extract_staged(
                output_dir.as_ref(),
                &options,
                &config.selection,
                Some(archive.as_ref()),
                progress,
                |dir, options, progress| {
                    extract_validated(archive.as_ref(), dir, config, options, progress)
                },
            )
        })
    }
}

/// Lists the contents of an archive without extracting it.
///
/// Holds the [`SecurityConfig`] whose quotas and path rules the listing
/// enforces, the [`ListOptions`] and an optional [`ProgressCallback`], which
/// sees one `on_entry_start` / `on_entry_complete` pair per listed entry
/// (`total` is unknown for TAR) and `on_complete` once after the manifest was
/// built. Nothing is written to disk.
///
/// # Errors
///
/// [`list`](Self::list) and [`list_reader`](Self::list_reader) return an error
/// if:
/// - the archive cannot be opened or its format is unsupported
/// - the archive is corrupted
/// - a quota is exceeded (file count, total size, single file size)
/// - declared compressed sizes exceed the archive length
///
/// A reader source is neither opened nor detected, so a malformed archive fails
/// as it would from a file. `on_complete` is not called on failure.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ListRequest;
/// use exarch_core::SecurityConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let manifest = ListRequest::new(&config).list("archive.tar.gz")?;
/// println!("{} entries", manifest.total_entries());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ListRequest<'a>(Carrier<'a, SecurityConfig, ListOptions>);

impl<'a> ListRequest<'a> {
    /// A listing under `config` with default options and no progress callback.
    #[must_use]
    pub fn new(config: &'a SecurityConfig) -> Self {
        Self(Carrier::new(config, ListOptions::default()))
    }

    /// Sets the listing options.
    #[must_use]
    pub fn with_options(self, options: ListOptions) -> Self {
        Self(self.0.with_options(options))
    }

    /// Reports progress to `progress`.
    #[must_use]
    pub fn with_progress(self, progress: &'a mut dyn ProgressCallback) -> Self {
        Self(self.0.with_progress(progress))
    }

    /// Lists the archive file at `archive`.
    ///
    /// # Errors
    ///
    /// See [`ListRequest`].
    pub fn list(self, archive: impl AsRef<Path>) -> Result<ArchiveManifest> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            crate::inspection::list_archive_with_progress(archive, config, options, progress)
        })
    }

    /// Lists an archive read from `reader`.
    ///
    /// # Errors
    ///
    /// See [`ListRequest`].
    pub fn list_reader(self, reader: ArchiveReader<'_>) -> Result<ArchiveManifest> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            let manifest = reader.list(
                config,
                &mut ListPass::strict_with(options.stored_targets).with_progress(progress),
            )?;
            progress.on_complete();
            Ok(manifest)
        })
    }

    /// Lists the archive at `archive` and keeps what extraction can reuse.
    ///
    /// `config` is the policy the **extraction** will run under. The list pass
    /// itself runs under the same quotas, path rules, allowlist and decoder
    /// limits with the flags that only matter once bytes are written (symlinks,
    /// hardlinks, world-writable files, preserved permissions) turned off, so
    /// that a listing never admits more than the extraction would. The
    /// returned [`ListedArchive`] extracts under `config`, so what was listed
    /// is what is extracted.
    ///
    /// `reuse` says where a ZIP archive keeps the output of its structural
    /// check for the extraction; for a compressed TAR the decoder output is
    /// spooled instead. See [`ListedArchive`].
    ///
    /// The progress callback, if any, sees the list pass's entry events;
    /// `on_complete` is left to the extraction.
    ///
    /// # Errors
    ///
    /// See [`ListRequest`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::DecodeReuse;
    /// use exarch_core::ListRequest;
    /// use exarch_core::SecurityConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let dir = tempfile::tempdir()?;
    /// # let archive = dir.path().join("a.tar");
    /// # let mut tar = tar::Builder::new(Vec::new());
    /// # let mut header = tar::Header::new_gnu();
    /// # header.set_size(2);
    /// # header.set_mode(0o644);
    /// # tar.append_data(&mut header, "a.txt", &b"hi"[..])?;
    /// # std::fs::write(&archive, tar.into_inner()?)?;
    /// let config = SecurityConfig::default();
    /// let listed = ListRequest::new(&config).for_extraction(&archive, DecodeReuse::default())?;
    /// assert_eq!(listed.manifest().total_entries(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn for_extraction(
        self,
        archive: impl AsRef<Path>,
        reuse: DecodeReuse,
    ) -> Result<ListedArchive> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            ListedArchive::list(archive.as_ref(), config, options, reuse, Some(progress))
        })
    }
}

/// Verifies an archive's security without extracting it.
///
/// Holds the [`SecurityConfig`] to validate against, the
/// [`VerificationOptions`] (whether to also check payload integrity) and an
/// optional [`ProgressCallback`], which sees one `on_entry_start` /
/// `on_entry_complete` pair per scanned entry and `on_complete` once when a
/// report is returned, including one whose status is `Fail`.
///
/// # Errors
///
/// [`verify`](Self::verify) and [`verify_reader`](Self::verify_reader) return
/// an error if:
/// - the archive cannot be opened or its format is unsupported
/// - the archive structure cannot be read, or declared compressed sizes exceed
///   the archive length
/// - an entry name is a path traversal: the listing step rejects it with
///   [`ArchiveError::PathTraversal`](crate::ArchiveError::PathTraversal) before
///   a report exists
/// - integrity is requested and a TAR entry's content fails to decode
///
/// Other security violations are reported in
/// [`VerificationReport::issues`]. `on_complete` is not called on failure.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::VerificationStatus;
/// use exarch_core::VerifyRequest;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let report = VerifyRequest::new(&config).verify("archive.zip")?;
/// assert_eq!(report.status(), VerificationStatus::Pass);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct VerifyRequest<'a>(Carrier<'a, SecurityConfig, VerificationOptions>);

impl<'a> VerifyRequest<'a> {
    /// A verification under `config` with default options and no progress
    /// callback.
    #[must_use]
    pub fn new(config: &'a SecurityConfig) -> Self {
        Self(Carrier::new(config, VerificationOptions::default()))
    }

    /// Sets the verification options.
    #[must_use]
    pub fn with_options(self, options: VerificationOptions) -> Self {
        Self(self.0.with_options(options))
    }

    /// Reports progress to `progress`.
    #[must_use]
    pub fn with_progress(self, progress: &'a mut dyn ProgressCallback) -> Self {
        Self(self.0.with_progress(progress))
    }

    /// Verifies the archive file at `archive`.
    ///
    /// # Errors
    ///
    /// See [`VerifyRequest`].
    pub fn verify(self, archive: impl AsRef<Path>) -> Result<VerificationReport> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            crate::inspection::verify_archive_with_progress(archive, config, options, progress)
        })
    }

    /// Verifies an archive read from `reader`; nothing is written and no
    /// filesystem path is needed.
    ///
    /// # Errors
    ///
    /// See [`VerifyRequest`].
    pub fn verify_reader(self, reader: ArchiveReader<'_>) -> Result<VerificationReport> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            let report = reader.verify(config, options, progress)?;
            progress.on_complete();
            Ok(report)
        })
    }
}

/// Extracts an archive read from a reader into an [`EntrySink`].
///
/// Every entry passes the validation pipeline of [`ExtractRequest`] and is then
/// delivered to the sink instead of being written under a directory. See the
/// [`sink`](crate::sink) module for what the sink may rely on and what it must
/// do. The optional [`ProgressCallback`] sees the events of a directory
/// extraction.
///
/// A 7z source is read in two phases: everything the file table can refuse
/// (admission, ratios, quotas, link policy, paths, name lengths) is refused
/// before the sink sees an entry, then the entries are decoded and delivered in
/// archive order.
///
/// # Errors
///
/// [`extract`](Self::extract) returns the errors of [`ExtractRequest`], plus
/// any error the sink returns: [`ArchiveError::Io`](crate::ArchiveError::Io) if
/// no entry was delivered yet,
/// [`ArchiveError::PartialExtraction`](crate::ArchiveError::PartialExtraction)
/// wrapping it afterwards. A sink that reports [`SinkFull`](crate::SinkFull)
/// ends the extraction with a
/// [`QuotaResource::SinkCapacity`](crate::QuotaResource::SinkCapacity) quota
/// error.
///
/// # Examples
///
/// ```
/// use std::io;
///
/// use exarch_core::ArchiveReader;
/// use exarch_core::MemorySink;
/// use exarch_core::SecurityConfig;
/// use exarch_core::SinkExtractRequest;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = tar::Builder::new(Vec::new());
/// let mut header = tar::Header::new_gnu();
/// header.set_size(2);
/// header.set_mode(0o644);
/// builder.append_data(&mut header, "a.txt", &b"hi"[..])?;
/// let bytes = builder.into_inner()?;
///
/// let mut sink = MemorySink::default();
/// let config = SecurityConfig::default();
/// let report = SinkExtractRequest::new(&config)
///     .extract(ArchiveReader::tar(io::Cursor::new(bytes), None), &mut sink)?;
/// assert_eq!(report.files_extracted, 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SinkExtractRequest<'a>(Carrier<'a, SecurityConfig, SinkOptions>);

impl<'a> SinkExtractRequest<'a> {
    /// An extraction into a sink under `config` with default options and no
    /// progress callback.
    #[must_use]
    pub fn new(config: &'a SecurityConfig) -> Self {
        Self(Carrier::new(config, SinkOptions::default()))
    }

    /// Sets the sink extraction options.
    #[must_use]
    pub fn with_options(self, options: SinkOptions) -> Self {
        Self(self.0.with_options(options))
    }

    /// Reports progress to `progress`.
    #[must_use]
    pub fn with_progress(self, progress: &'a mut dyn ProgressCallback) -> Self {
        Self(self.0.with_progress(progress))
    }

    /// Extracts `reader` into `sink`.
    ///
    /// # Errors
    ///
    /// See [`SinkExtractRequest`].
    pub fn extract<S: EntrySink>(
        self,
        reader: ArchiveReader<'_>,
        sink: &mut S,
    ) -> Result<ExtractionReport> {
        let Self(request) = self;
        request.run(|config, options, progress| {
            extract_to_sink_reusing(reader, sink, config, options, progress, None)
        })
    }
}

/// Whether creating an output file may replace one that already exists.
///
/// There is no default: the caller states which it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputPolicy {
    /// Refuse with
    /// [`ArchiveError::OutputExists`](crate::ArchiveError::OutputExists)
    /// when anything is at the path.
    CreateNew,
    /// Replace a regular file, or a symlink at the path (the link itself, not
    /// its destination), atomically when the archive is complete.
    Replace,
}

closed_enum! {
    /// Whether a created archive is flushed to stable storage before it is
    /// reported as written.
    ///
    /// `Synced` (the default) flushes the archive file and then, on Unix, its
    /// parent directory entry, so a published archive survives a crash or
    /// power loss. A directory that cannot be synced does not fail the
    /// creation, since the archive is already published: it adds a
    /// [`CreationWarning::DirectoryNotSynced`](crate::CreationWarning::DirectoryNotSynced)
    /// to the report. On Windows and
    /// WASI the directory entry is not flushed and no warning is raised; only
    /// the file is.
    ///
    /// `Unsynced` skips both flushes and is faster, with these hazards:
    ///
    /// - After a crash or power loss a [`Replace`](OutputPolicy::Replace)
    ///   target can be empty or truncated, and a
    ///   [`CreateNew`](OutputPolicy::CreateNew) file can be empty.
    /// - Write-back errors (network filesystems, quotas, delayed-allocation
    ///   `ENOSPC`) are not reported, so an `Ok` result does not mean the bytes
    ///   reached the disk.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Durability;
    /// use exarch_core::OutputFile;
    ///
    /// assert_eq!(Durability::default(), Durability::Synced);
    /// let out = OutputFile::replace("scratch.tar").with_durability(Durability::Unsynced);
    /// assert_eq!(out.durability(), Durability::Unsynced);
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum Durability {
        /// Flush the file and its directory entry before reporting success
        #[default]
        Synced => "synced",

        /// Skip the flushes; see the type documentation for the hazards
        Unsynced => "unsynced",
    }
}

/// How the archive format of an [`OutputFile`] is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OutputFormat {
    /// From the file extension. The ZIP-based extensions that need structure
    /// exarch does not produce (`.apk`, `.whl`, `.epub`, ...) are refused.
    #[default]
    FromExtension,
    /// The given format, whatever the extension is. This is how a ZIP-based
    /// extension is written as a plain ZIP.
    Explicit(CreatableFormat),
}

/// The archive file a creation writes: its path, whether it may replace an
/// existing file and how its format is chosen.
///
/// The archive is staged in a temporary file in the target's directory (which
/// must be writable) and renamed into place only when it is complete, so a
/// failed creation leaves the path as it was. The output must be absent, a
/// regular file, or a symlink to one (or dangling); a directory, a FIFO or a
/// device is refused with
/// [`InvalidConfiguration`](crate::ArchiveError::InvalidConfiguration).
///
/// Replacing keeps the permission bits of the file that is replaced (a symlink
/// is resolved first), never wider than before and without setuid, setgid or
/// sticky bits; a new file gets `0o666` filtered by the umask. Owner, group,
/// ACLs and extended attributes of a replaced file are not preserved: the new
/// file belongs to the creating user and to the group the filesystem gives a
/// new file in that directory (the directory's group on macOS and BSD), so a
/// file that was shared through its group can become readable by another group
/// under the same mode bits.
///
/// The staged file and the target are never archived, even when a source
/// directory contains them. They are recognized by file name and canonical
/// parent directory, so an alias of the output directory that canonicalization
/// does not resolve (a bind or `nullfs` mount of it inside a source tree) is
/// not recognized and the output may be archived into itself. Do not put such
/// a mount under a source.
///
/// A [`ProgressCallback`] that reports
/// [`is_cancelled`](ProgressCallback::is_cancelled) stops the creation: nothing
/// is published and a previous output stays as it was. After the archive is
/// published the parent directory is synced on a best-effort basis (Unix).
///
/// # Examples
///
/// ```
/// use exarch_core::CreatableFormat;
/// use exarch_core::OutputFile;
/// use exarch_core::OutputFormat;
/// use exarch_core::OutputPolicy;
///
/// let out = OutputFile::replace("backup.tar.gz");
/// assert_eq!(out.policy(), OutputPolicy::Replace);
/// assert_eq!(out.format(), OutputFormat::FromExtension);
///
/// let out = OutputFile::create_new("bundle.apk").with_format(CreatableFormat::Zip);
/// assert_eq!(out.format(), OutputFormat::Explicit(CreatableFormat::Zip));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFile {
    path: PathBuf,
    policy: OutputPolicy,
    format: OutputFormat,
    durability: Durability,
}

impl OutputFile {
    /// An output at `path` that must not exist yet.
    #[must_use]
    pub fn create_new(path: impl Into<PathBuf>) -> Self {
        Self::at(path.into(), OutputPolicy::CreateNew)
    }

    /// An output at `path` that replaces an existing file.
    #[must_use]
    pub fn replace(path: impl Into<PathBuf>) -> Self {
        Self::at(path.into(), OutputPolicy::Replace)
    }

    const fn at(path: PathBuf, policy: OutputPolicy) -> Self {
        Self {
            path,
            policy,
            format: OutputFormat::FromExtension,
            durability: Durability::Synced,
        }
    }

    /// Writes `format` instead of the one the extension names.
    #[must_use]
    pub const fn with_format(mut self, format: CreatableFormat) -> Self {
        self.format = OutputFormat::Explicit(format);
        self
    }

    /// Sets whether the archive is flushed to stable storage before success is
    /// reported.
    #[must_use]
    pub const fn with_durability(mut self, durability: Durability) -> Self {
        self.durability = durability;
        self
    }

    /// The output path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether an existing file may be replaced.
    #[must_use]
    pub const fn policy(&self) -> OutputPolicy {
        self.policy
    }

    /// How the format is chosen.
    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    /// Whether the archive is flushed to stable storage.
    #[must_use]
    pub const fn durability(&self) -> Durability {
        self.durability
    }
}

/// Creates an archive from files and directories.
///
/// Holds the [`CreationConfig`] and an optional [`ProgressCallback`]; the
/// destination is chosen by the terminal method: a file
/// ([`create`](Self::create)), a writer ([`write`](Self::write)) or memory
/// ([`to_bytes`](Self::to_bytes)).
///
/// # Errors
///
/// All terminals return an error if:
/// - a source does not exist or cannot be read
/// - the configuration is invalid
/// - writing the archive fails
///
/// [`create`](Self::create) also returns an error if the output is refused (see
/// [`OutputFile`]) or its format cannot be determined. Sources are validated
/// before the output is published, so a failed creation leaves no archive.
///
/// # Examples
///
/// ```
/// use exarch_core::CreateRequest;
/// use exarch_core::CreationConfig;
/// use exarch_core::OutputFile;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = tempfile::tempdir()?;
/// std::fs::write(dir.path().join("a.txt"), b"hello")?;
///
/// let config = CreationConfig::default();
/// let output = dir.path().join("out.tar.gz");
/// let report = CreateRequest::new(&config).create(
///     &OutputFile::create_new(&output),
///     &[dir.path().join("a.txt")],
/// )?;
/// assert_eq!(report.files_added, 1);
/// assert!(output.exists());
///
/// let missing = dir.path().join("missing.tar.gz");
/// assert!(
///     CreateRequest::new(&config)
///         .create(
///             &OutputFile::create_new(&missing),
///             &[dir.path().join("nope")]
///         )
///         .is_err()
/// );
/// assert!(!missing.exists());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CreateRequest<'a>(Carrier<'a, CreationConfig, ()>);

impl<'a> CreateRequest<'a> {
    /// A creation under `config` with no progress callback.
    #[must_use]
    pub const fn new(config: &'a CreationConfig) -> Self {
        Self(Carrier::new(config, ()))
    }

    /// Reports progress to `progress`.
    #[must_use]
    pub fn with_progress(self, progress: &'a mut dyn ProgressCallback) -> Self {
        Self(self.0.with_progress(progress))
    }

    /// Creates the archive at `output` from `sources`.
    ///
    /// `CreationReport::bytes_compressed` is the size of the archive file.
    ///
    /// # Errors
    ///
    /// See [`CreateRequest`].
    pub fn create<P: AsRef<Path>>(
        self,
        output: &OutputFile,
        sources: &[P],
    ) -> Result<CreationReport> {
        let format = resolve_output_format(output)?;
        let mut staged = StagedOutput::begin(output.path(), output.policy())?;
        let mut report = self
            .0
            .run(|config, (), progress| -> Result<CreationReport> {
                let report = write_staged(&mut staged, format, sources, config, progress)?;
                check_cancelled(progress)?;
                Ok(report)
            })?;
        if let Some(warning) = staged.commit(output.durability())? {
            report.add_warning(warning);
        }
        Ok(report)
    }

    /// Creates the archive from `sources` into `writer`.
    ///
    /// The writer fixes the format. `CreationReport::bytes_compressed` is the
    /// number of bytes written to it.
    ///
    /// # Errors
    ///
    /// See [`CreateRequest`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveWriter;
    /// use exarch_core::CompressionCodec;
    /// use exarch_core::CreateRequest;
    /// use exarch_core::CreationConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let src = tempfile::tempdir()?;
    /// std::fs::write(src.path().join("a.txt"), b"hello")?;
    ///
    /// let mut buf = Vec::new();
    /// let config = CreationConfig::default();
    /// let report = CreateRequest::new(&config).write(
    ///     ArchiveWriter::tar(&mut buf, Some(CompressionCodec::Gzip)),
    ///     &[src.path()],
    /// )?;
    /// assert_eq!(report.bytes_compressed, buf.len() as u64);
    /// # Ok(())
    /// # }
    /// ```
    pub fn write<P: AsRef<Path>>(
        self,
        writer: ArchiveWriter<'_>,
        sources: &[P],
    ) -> Result<CreationReport> {
        self.0
            .run(|config, (), progress| writer.write(sources, config, progress))
    }

    /// Creates an archive of `format` from `sources` and returns its bytes.
    ///
    /// The whole archive is held in memory, so use [`create`](Self::create) for
    /// large ones. Because the finished ZIP can be read back, a ZIP result
    /// carries the same warning as [`create`](Self::create) when default
    /// extraction would refuse an entry as a zip bomb.
    ///
    /// # Errors
    ///
    /// See [`CreateRequest`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::CreatableFormat;
    /// use exarch_core::CreateRequest;
    /// use exarch_core::CreationConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let src = tempfile::tempdir()?;
    /// std::fs::write(src.path().join("a.txt"), b"hello")?;
    ///
    /// let config = CreationConfig::default();
    /// let (bytes, report) =
    ///     CreateRequest::new(&config).to_bytes(CreatableFormat::TarGz, &[src.path()])?;
    /// assert_eq!(report.bytes_compressed, bytes.len() as u64);
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_bytes<P: AsRef<Path>>(
        self,
        format: CreatableFormat,
        sources: &[P],
    ) -> Result<(Vec<u8>, CreationReport)> {
        let mut out = Cursor::new(Vec::new());
        let mut report = self.write(ArchiveWriter::of_type(&mut out, format), sources)?;
        if format == CreatableFormat::Zip {
            warn_on_extraction_ratio(&mut out, &mut report);
        }
        Ok((out.into_inner(), report))
    }
}

/// Writes the archive of `format` into the staged file, which a ZIP can be
/// read back from for the extraction-ratio warning.
fn write_staged<P: AsRef<Path>>(
    staged: &mut StagedOutput,
    format: CreatableFormat,
    sources: &[P],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let (file, excluded) = staged.parts();
    match format.family() {
        CreationFamily::Tar(codec) => write_tar(file, codec, sources, config, excluded, progress),
        CreationFamily::Zip => {
            let (mut report, file) = write_zip(file, sources, config, excluded, progress)?;
            warn_on_extraction_ratio(file, &mut report);
            Ok(report)
        }
    }
}
