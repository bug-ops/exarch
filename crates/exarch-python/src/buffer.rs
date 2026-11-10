//! Archives held in memory instead of on disk.

use std::num::NonZeroU64;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ArchiveType;
use exarch_core::CallbackEntry;
use exarch_core::CallbackError;
use exarch_core::ClosedEnum;
use exarch_core::ConfigSetting;
use exarch_core::CreatableFormat;
use exarch_core::CreateRequest;
use exarch_core::DecodeReuse;
use exarch_core::DecodeReuseKind;
use exarch_core::ListRequest;
use exarch_core::MemoryEntry;
use exarch_core::MemoryEntryKind;
use exarch_core::MemoryExtractRequest;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PartialWrites;
use exarch_core::PathModel;
use exarch_core::ReuseLimit;
use exarch_core::SanitizedMode;
use exarch_core::VerifyRequest;
use exarch_core::VolumeIdentity;
use exarch_core::extract_reader_to_callback;
use exarch_core::extract_reader_to_memory;
use exarch_core::utf8_entry_path;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::catch_panic_as_py_err;
use crate::catch_panic_as_py_result;
use crate::config::PyCreationConfig;
use crate::config::PyInteger;
use crate::config::PyListOptions;
use crate::config::PySecurityConfig;
use crate::config::PyVerificationOptions;
use crate::config::parse_existing_files;
use crate::error::convert_error;
use crate::path_to_boundary;
use crate::report::PyArchiveManifest;
use crate::report::PyCreationReport;
use crate::report::PyExtractionReport;
use crate::report::PyVerificationReport;
use crate::run_with_optional_progress;
use crate::stream::ArchiveInput;

/// Parses the string form of a closed core enum.
///
/// # Errors
///
/// `InvalidConfigurationError` naming `setting` with `NotOneOf` for any other
/// string.
pub fn parse_one<T: ClosedEnum>(setting: ConfigSetting, value: &str) -> PyResult<T> {
    T::parse_for(setting, value).map_err(convert_error)
}

/// Parses an optional string form of a closed core enum.
fn parse_variant<T: ClosedEnum>(
    setting: ConfigSetting,
    value: Option<&str>,
) -> PyResult<Option<T>> {
    value.map(|value| parse_one(setting, value)).transpose()
}

/// Parses the string form of a format that can be created.
pub fn parse_creatable_format(format: &str) -> PyResult<CreatableFormat> {
    format.parse().map_err(convert_error)
}

/// Parses the string form shared with `ArchiveType::as_str`.
fn parse_format(format: Option<&str>) -> PyResult<Option<ArchiveType>> {
    parse_variant(ConfigSetting::ArchiveFormat, format)
}

/// Parses the string form shared with `PathModel::as_str`.
fn parse_path_model(path_model: Option<&str>) -> PyResult<Option<PathModel>> {
    parse_variant(ConfigSetting::PathModel, path_model)
}

/// An entry extracted into memory.
///
/// The concrete class tells what the entry holds: `MemoryFile`,
/// `MemoryDirectory`, `MemorySymlink` or `MemoryHardlink` (the last only from
/// `extract_archive_to_callback`). Each carries only the attributes of its
/// kind.
///
/// # Attributes
///
/// * `path` - Entry path, relative, as delivered by extraction
/// * `kind` - `"file"`, `"directory"`, `"symlink"` or `"hardlink"`
#[pyclass(name = "MemoryEntry", subclass, frozen)]
pub struct PyMemoryEntry {
    path: String,
    kind: &'static str,
}

#[pymethods]
impl PyMemoryEntry {
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    #[getter]
    const fn kind(&self) -> &'static str {
        self.kind
    }
}

/// A regular file extracted into memory.
///
/// # Attributes
///
/// * `data` - The file's bytes
/// * `mode` - Permission bits after setuid and setgid were stripped (`None`
///   unless the archive carries a mode)
#[pyclass(name = "MemoryFile", extends = PyMemoryEntry, frozen)]
pub struct PyMemoryFile {
    data: Py<PyBytes>,
    mode: Option<u32>,
}

#[pymethods]
impl PyMemoryFile {
    #[classattr]
    fn kind() -> &'static str {
        MemoryEntryKind::File.as_str()
    }

    #[getter]
    fn data(&self, py: Python<'_>) -> Py<PyBytes> {
        self.data.clone_ref(py)
    }

    #[getter]
    fn mode(&self) -> Option<u32> {
        self.mode
    }

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("MemoryFile(path={:?})", slf.as_super().get().path)
    }
}

/// A directory the archive names explicitly, extracted into memory.
#[pyclass(name = "MemoryDirectory", extends = PyMemoryEntry, frozen)]
pub struct PyMemoryDirectory;

#[pymethods]
impl PyMemoryDirectory {
    #[classattr]
    fn kind() -> &'static str {
        MemoryEntryKind::Directory.as_str()
    }

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("MemoryDirectory(path={:?})", slf.as_super().get().path)
    }
}

/// A symbolic link stored as data.
///
/// # Attributes
///
/// * `target` - The target as the archive spells it, relative to the link
#[pyclass(name = "MemorySymlink", extends = PyMemoryEntry, frozen)]
pub struct PyMemorySymlink {
    target: String,
}

#[pymethods]
impl PyMemorySymlink {
    #[classattr]
    fn kind() -> &'static str {
        MemoryEntryKind::Symlink.as_str()
    }

    #[getter]
    fn target(&self) -> &str {
        &self.target
    }

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("MemorySymlink(path={:?})", slf.as_super().get().path)
    }
}

/// A hard link to an already delivered entry, by reference.
///
/// # Attributes
///
/// * `target` - The root-relative resolved path of an already delivered entry,
///   a file or an earlier hardlink
#[pyclass(name = "MemoryHardlink", extends = PyMemoryEntry, frozen)]
pub struct PyMemoryHardlink {
    target: String,
}

#[pymethods]
impl PyMemoryHardlink {
    #[classattr]
    fn kind() -> &'static str {
        MemoryEntryKind::Hardlink.as_str()
    }

    #[getter]
    fn target(&self) -> &str {
        &self.target
    }

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("MemoryHardlink(path={:?})", slf.as_super().get().path)
    }
}

impl PyMemoryEntry {
    fn new(py: Python<'_>, path: &Path, entry: CallbackEntry) -> PyResult<Py<Self>> {
        let base = Self {
            path: utf8(path)?,
            kind: entry.kind().as_str(),
        };
        match entry {
            CallbackEntry::Stored(MemoryEntry::File { data, mode }) => Bound::new(
                py,
                PyClassInitializer::from(base).add_subclass(PyMemoryFile {
                    data: PyBytes::new(py, &data).unbind(),
                    mode: mode.map(SanitizedMode::as_u32),
                }),
            )
            .map(|entry| entry.into_super().unbind()),
            CallbackEntry::Stored(MemoryEntry::Directory) => Bound::new(
                py,
                PyClassInitializer::from(base).add_subclass(PyMemoryDirectory),
            )
            .map(|entry| entry.into_super().unbind()),
            CallbackEntry::Stored(MemoryEntry::Symlink { target }) => Bound::new(
                py,
                PyClassInitializer::from(base).add_subclass(PyMemorySymlink {
                    target: utf8(&target)?,
                }),
            )
            .map(|entry| entry.into_super().unbind()),
            CallbackEntry::Hardlink { target } => Bound::new(
                py,
                PyClassInitializer::from(base).add_subclass(PyMemoryHardlink {
                    target: utf8(target.as_path())?,
                }),
            )
            .map(|entry| entry.into_super().unbind()),
            _ => Bound::new(py, PyClassInitializer::from(base)).map(Bound::unbind),
        }
    }
}

/// The text of `path`, or an error: a lossy conversion could merge two
/// distinct entries into one name.
fn utf8(path: &Path) -> PyResult<String> {
    utf8_entry_path(path)
        .map(str::to_owned)
        .map_err(|malformation| convert_error(ArchiveError::from(malformation)))
}

/// Builds the core policy from the two Python arguments; core owns the pairing
/// rule.
fn build_decode_reuse(kind: DecodeReuseKind, limit: Option<PyInteger>) -> PyResult<DecodeReuse> {
    let limit = limit
        .map(|bytes| {
            bytes
                .positive(ConfigSetting::DecodeReuseLimit)
                .map(ReuseLimit::new)
        })
        .transpose()?;
    DecodeReuse::from_parts(kind, limit).map_err(convert_error)
}

/// What the in-memory and callback extraction functions honour of the options
/// of path-based extraction.
///
/// Atomic extraction renames a directory, which an in-memory extraction does
/// not have, so only the existing-files policy and the ZIP decode reuse remain.
///
/// # Arguments
///
/// * `existing_files` - `"skip"` (default) skips an entry whose path an earlier
///   entry already holds and counts a duplicate; `"overwrite"` delivers it
///   again; `"refuse"` fails with `OutputExistsError`
/// * `decode_reuse` - `"off"` (default), `"memory"` or `"temp_file"`: where a
///   ZIP extraction keeps the output of its structural check so deflate entries
///   are decoded once instead of twice. `"temp_file"` writes the plaintext of
///   the archive to the temporary directory until the extraction ends.
/// * `decode_reuse_limit` - The most bytes kept, at most 256 MiB (default 32
///   MiB); only with `"memory"` or `"temp_file"`
#[pyclass(name = "SinkOptions", frozen)]
#[derive(Clone)]
pub struct PySinkOptions {
    inner: exarch_core::SinkOptions,
}

#[pymethods]
impl PySinkOptions {
    #[new]
    #[pyo3(signature = (existing_files=None, decode_reuse=None, decode_reuse_limit=None))]
    #[pyo3(text_signature = "(existing_files=None, decode_reuse=None, decode_reuse_limit=None)")]
    fn new(
        existing_files: Option<&str>,
        decode_reuse: Option<&str>,
        decode_reuse_limit: Option<PyInteger>,
    ) -> PyResult<Self> {
        let defaults = exarch_core::SinkOptions::default();
        let kind = decode_reuse.map_or(Ok(defaults.decode_reuse.kind()), |text| {
            parse_one(ConfigSetting::DecodeReuse, text)
        })?;
        Ok(Self {
            inner: defaults
                .with_existing_files(
                    existing_files.map_or(Ok(defaults.existing_files), parse_existing_files)?,
                )
                .with_decode_reuse(build_decode_reuse(kind, decode_reuse_limit)?),
        })
    }

    #[getter]
    const fn existing_files(&self) -> &'static str {
        self.inner.existing_files.as_str()
    }

    #[getter]
    const fn decode_reuse(&self) -> &'static str {
        self.inner.decode_reuse.kind().as_str()
    }

    #[getter]
    fn decode_reuse_limit(&self) -> Option<u64> {
        self.inner.decode_reuse.limit().map(ReuseLimit::get)
    }

    fn __repr__(&self) -> String {
        format!(
            "SinkOptions(existing_files={:?}, decode_reuse={:?}, decode_reuse_limit={:?})",
            self.existing_files(),
            self.decode_reuse(),
            self.decode_reuse_limit(),
        )
    }
}

impl PySinkOptions {
    const fn as_core(&self) -> exarch_core::SinkOptions {
        self.inner
    }
}

/// Validates `max_bytes`: a positive count that fits in 64 bits.
fn parse_max_bytes(max_bytes: Option<PyInteger>) -> PyResult<Option<NonZeroU64>> {
    max_bytes
        .map(|bytes| bytes.positive(exarch_core::ConfigSetting::MaxBytes))
        .transpose()
}

/// The result of [`extract_archive_to_memory`].
///
/// # Attributes
///
/// * `report` - The `ExtractionReport`
/// * `entries` - The extracted entries in path order
#[pyclass(name = "MemoryExtraction", frozen)]
pub struct PyMemoryExtraction {
    report: PyExtractionReport,
    entries: Vec<Py<PyMemoryEntry>>,
}

#[pymethods]
impl PyMemoryExtraction {
    #[getter]
    fn report(&self) -> PyExtractionReport {
        self.report.clone()
    }

    #[getter]
    fn entries(&self, py: Python<'_>) -> Vec<Py<PyMemoryEntry>> {
        self.entries
            .iter()
            .map(|entry| entry.clone_ref(py))
            .collect()
    }
}

/// Extract an archive held in memory into memory.
///
/// The archive passes the same validation as `extract_archive`; nothing is
/// written to disk.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `SinkOptions`
/// * `max_bytes` - The most bytes to keep: payload (file data, hardlink copies
///   and symlink targets) plus path bytes plus 256 per entry; defaults to the
///   config's `max_total_size`
/// * `path_model` - `"host"` (default) or `"portable"`: validate names against
///   this platform's rules or the strictest rules of every platform
/// * `format` - The archive format; detected from the leading bytes if None
///
/// # Returns
///
/// `MemoryExtraction` with the report and the extracted entries
///
/// # Raises
///
/// * `ValueError` - Unknown `format` or `path_model`, or `max_bytes` of zero
/// * `QuotaExceededError` - A quota, or `max_bytes`, was exceeded
/// * The exceptions of `extract_archive`
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive_to_memory
///
/// with open("archive.tar.gz", "rb") as f:
///     result = extract_archive_to_memory(f.read())
/// for entry in result.entries:
///     print(entry.path, entry.kind)
/// ```
#[pyfunction]
#[pyo3(signature = (data, config=None, options=None, max_bytes=None, path_model=None, format=None))]
pub fn extract_archive_to_memory(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<&PySinkOptions>,
    max_bytes: Option<PyInteger>,
    path_model: Option<&str>,
    format: Option<&str>,
) -> PyResult<PyMemoryExtraction> {
    let request = MemoryRequest::parse(config, options, max_bytes, path_model, format)?;

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive extraction", || {
        py.detach(|| request.run(data, &mut exarch_core::NoopProgress))
    });
    let (report, sink) = slot.surface(result)?;
    into_py_extraction(py, report, sink)
}

/// Extract an archive held in memory into memory, with a progress callback.
///
/// Same as `extract_archive_to_memory`, plus `progress`, called once per entry
/// with `(path: str, total: int, current: int, bytes_written: int)`.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `SinkOptions`
/// * `max_bytes` - See `extract_archive_to_memory`
/// * `path_model` - See `extract_archive_to_memory`
/// * `format` - The archive format; detected from the leading bytes if None
/// * `progress` - Optional progress callback function
///
/// # Returns
///
/// `MemoryExtraction` with the report and the extracted entries
///
/// # Raises
///
/// * The exceptions of `extract_archive_to_memory`
/// * Whatever `progress` itself raises - see the note below
///
/// # A raising `progress` propagates instead of being swallowed
///
/// A raising `progress` cancels the extraction at the next entry and is not
/// called again.
///
/// - The callback's exception is what propagates, with a
///   `progress_callback_error = True` marker and a `writes = "discarded"`
///   attribute, because nothing was written to disk; it carries no counters.
/// - If extraction fails for its own reason first, the core error takes
///   priority and the callback's exception is chained onto it via `__cause__`.
///
/// The GIL is released during extraction and taken once per callback.
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive_to_memory_with_progress
///
/// def progress(path, total, current, bytes_written):
///     print(f"{current}/{total}: {path}")
///
/// with open("archive.tar.gz", "rb") as f:
///     result = extract_archive_to_memory_with_progress(f.read(), progress=progress)
/// ```
#[pyfunction]
#[expect(
    clippy::too_many_arguments,
    reason = "the signature mirrors the sibling function"
)]
#[pyo3(signature = (data, config=None, options=None, max_bytes=None, path_model=None, format=None, progress=None))]
pub fn extract_archive_to_memory_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<&PySinkOptions>,
    max_bytes: Option<PyInteger>,
    path_model: Option<&str>,
    format: Option<&str>,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyMemoryExtraction> {
    let request = MemoryRequest::parse(config, options, max_bytes, path_model, format)?;

    let slot = data.failure_slot();
    let result = run_with_optional_progress(
        py,
        "archive extraction with progress",
        progress,
        |progress| request.run(data, progress),
        |exc, _| {
            let _ = exc.setattr("writes", PartialWrites::Discarded.as_str());
        },
    );
    let (report, sink) = slot.surface(result)?;
    into_py_extraction(py, report, sink)
}

/// List the contents of an archive held in memory, with a progress callback.
///
/// Same as `list_archive_bytes`, plus `progress`, called once per entry with
/// `(path: str, total: int | None, current: int, bytes_written: int)`. `total`
/// is `None` for TAR (the count is not known up front), and `bytes_written` is
/// always 0.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `ListOptions`, as in `list_archive`
/// * `format` - The archive format; detected from the leading bytes if None
/// * `progress` - Optional progress callback function
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Raises
///
/// * The exceptions of `list_archive_bytes`
/// * Whatever `progress` itself raises: it cancels the listing at the next
///   entry, and its exception is raised with a `progress_callback_error = True`
///   marker. If listing failed for its own reason first, the core error is
///   raised with the callback's exception as `__cause__`.
///
/// # Examples
///
/// ```python
/// from exarch import list_archive_bytes_with_progress
///
/// def progress(path, total, current, bytes_written):
///     print(f"{current}/{total}: {path}")
///
/// with open("archive.zip", "rb") as f:
///     manifest = list_archive_bytes_with_progress(f.read(), progress=progress)
/// ```
#[pyfunction]
#[pyo3(signature = (data, config=None, options=None, format=None, progress=None))]
pub fn list_archive_bytes_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyListOptions>>,
    format: Option<&str>,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyArchiveManifest> {
    let format = parse_format(format)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyListOptions::snapshot(options);

    let slot = data.failure_slot();
    let result = run_with_optional_progress(
        py,
        "archive listing with progress",
        progress,
        |progress| {
            let reader = data.into_reader(format)?;
            ListRequest::new(&config)
                .with_options(options)
                .with_progress(progress)
                .list_reader(reader)
                .map(|manifest| {
                    PyArchiveManifest::new(manifest, &config, VolumeIdentity::default())
                })
        },
        |_, _| {},
    );
    slot.surface(result)
}

/// Verify the security of an archive held in memory, with a progress callback.
///
/// Same as `verify_archive_bytes`, plus `progress`, called once per entry with
/// `(path: str, total: int | None, current: int, bytes_written: int)`. `total`
/// is `None` for TAR (the count is not known up front), and `bytes_written` is
/// always 0.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if None
/// * `progress` - Optional progress callback function
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Raises
///
/// * The exceptions of `verify_archive_bytes`
/// * Whatever `progress` itself raises: it cancels the verification at the next
///   entry, and its exception is raised with a `progress_callback_error = True`
///   marker. If verification errored for its own reason first, the core error
///   is raised with the callback's exception as `__cause__`.
///
/// # Examples
///
/// ```python
/// from exarch import verify_archive_bytes_with_progress
///
/// def progress(path, total, current, bytes_written):
///     print(f"{current}/{total}: {path}")
///
/// with open("archive.zip", "rb") as f:
///     report = verify_archive_bytes_with_progress(f.read(), progress=progress)
/// ```
#[pyfunction]
#[pyo3(signature = (data, config=None, options=None, format=None, progress=None))]
pub fn verify_archive_bytes_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyVerificationOptions>>,
    format: Option<&str>,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyVerificationReport> {
    let format = parse_format(format)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyVerificationOptions::snapshot(options);

    let slot = data.failure_slot();
    let result = run_with_optional_progress(
        py,
        "archive verification with progress",
        progress,
        |progress| {
            let reader = data.into_reader(format)?;
            VerifyRequest::new(&config)
                .with_options(options)
                .with_progress(progress)
                .verify_reader(reader)
        },
        |_, _| {},
    );
    let report = slot.surface(result)?;

    Ok(PyVerificationReport::from(report))
}

/// Extract an archive held in memory, handing every verified entry to a
/// callback.
///
/// Nothing is written to disk and nothing is kept: `on_entry` receives a
/// `MemoryEntry` per entry, in extraction order, after the entry was verified
/// (a file arrives whole, after its declared size was checked). Memory use is
/// one file at a time, bounded by the config's `max_file_size`.
///
/// # Arguments
///
/// * `data` - The archive bytes, or a binary file object
/// * `on_entry` - Called with each `MemoryEntry`; its return value is ignored
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `SinkOptions`
/// * `path_model` - `"host"` (default) or `"portable"`
/// * `format` - The archive format; detected from the leading bytes if None
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Raises
///
/// * `TypeError` - `on_entry` is not callable
/// * `ValueError` - Unknown `format` or `path_model`
/// * Whatever `on_entry` raises, unchanged: the first exception stops the
///   extraction and is re-raised as is, with no marker or attribute added
/// * The exceptions of `extract_archive`
///
/// # Entries are provisional
///
/// An entry is delivered as soon as it is verified, before the rest of the
/// archive is read. A later failure refuses the archive after earlier entries
/// were already delivered, so treat the results as final only once the call
/// returned. The size of a file is checked, and so is the stream-level
/// checksum, but last: the gzip CRC of a `.tar.gz` is verified after the
/// end-of-archive marker, so a corrupt compressed stream refuses the archive
/// only after its entries were delivered.
///
/// # Entry kinds
///
/// A `"symlink"` entry's `target` is spelled as the archive stores it, relative
/// to the link. A `"hardlink"` entry is delivered by reference, after every
/// other entry: its `target` is the root-relative resolved path of an entry
/// that was already delivered, a file or an earlier hardlink (a chain is
/// delivered link by link), and no bytes are repeated. With
/// `SinkOptions(existing_files="overwrite")` one path can be
/// delivered more than once and a hardlink refers to the latest delivery.
/// Implicit parent directories are not delivered. The GIL is released during
/// I/O and taken once per entry.
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive_to_callback
///
/// sizes = {}
/// def on_entry(entry):
///     if entry.kind == "file":
///         sizes[entry.path] = len(entry.data)
///
/// with open("archive.tar.gz", "rb") as f:
///     report = extract_archive_to_callback(f.read(), on_entry)
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 extracts on_entry as an owned Py<PyAny>; the Send handle is what the py.detach closure borrows"
)]
#[pyo3(signature = (data, on_entry, config=None, options=None, path_model=None, format=None))]
pub fn extract_archive_to_callback(
    py: Python<'_>,
    data: ArchiveInput,
    on_entry: Py<PyAny>,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<&PySinkOptions>,
    path_model: Option<&str>,
    format: Option<&str>,
) -> PyResult<PyExtractionReport> {
    if !on_entry.bind(py).is_callable() {
        return Err(PyTypeError::new_err("on_entry must be callable"));
    }
    let request = MemoryRequest::parse(config, options, None, path_model, format)?;

    let slot = data.failure_slot();
    // Outer `Err`: an archive or file-object failure; inner `Err`: the
    // callback's own exception, which the file-object slot must never replace.
    let outcome = catch_panic_as_py_result("archive extraction to a callback", || {
        py.detach(|| {
            let reader = data.into_reader(request.format).map_err(convert_error)?;
            match extract_reader_to_callback(
                reader,
                &request.request,
                |path, entry| {
                    Python::attach(|py| {
                        let entry = PyMemoryEntry::new(py, path.as_path(), entry)?;
                        on_entry.call1(py, (entry,)).map(drop)
                    })
                },
                &mut exarch_core::NoopProgress,
            ) {
                Ok(report) => Ok(Ok(report)),
                Err(CallbackError::Callback(err)) => Ok(Err(err)),
                Err(CallbackError::Archive(err)) => Err(convert_error(err)),
            }
        })
    });
    let result = match outcome {
        Ok(Err(callback_error)) => return Err(callback_error),
        Ok(Ok(report)) => Ok(report),
        Err(err) => Err(err),
    };
    slot.surface(result).map(PyExtractionReport::from)
}

/// The validated arguments shared by the in-memory extraction functions.
struct MemoryRequest {
    request: MemoryExtractRequest,
    format: Option<ArchiveType>,
}

impl MemoryRequest {
    fn parse(
        config: Option<PyRef<'_, PySecurityConfig>>,
        options: Option<&PySinkOptions>,
        max_bytes: Option<PyInteger>,
        path_model: Option<&str>,
        format: Option<&str>,
    ) -> PyResult<Self> {
        let format = parse_format(format)?;
        let path_model = parse_path_model(path_model)?.unwrap_or_default();
        let max_bytes = parse_max_bytes(max_bytes)?;
        let config = PySecurityConfig::snapshot(config);
        let options =
            options.map_or_else(exarch_core::SinkOptions::default, PySinkOptions::as_core);
        let mut request = MemoryExtractRequest::default()
            .with_config(config)
            .with_options(options)
            .with_path_model(path_model);
        if let Some(bytes) = max_bytes {
            request = request.with_limit(MemoryLimit::new(bytes));
        }
        Ok(Self { request, format })
    }

    fn run(
        &self,
        data: ArchiveInput,
        progress: &mut dyn exarch_core::ProgressCallback,
    ) -> exarch_core::Result<(exarch_core::ExtractionReport, MemorySink)> {
        let reader = data.into_reader(self.format)?;
        extract_reader_to_memory(reader, &self.request, progress)
    }
}

fn into_py_extraction(
    py: Python<'_>,
    report: exarch_core::ExtractionReport,
    sink: MemorySink,
) -> PyResult<PyMemoryExtraction> {
    let entries = sink
        .into_entries()
        .into_iter()
        .map(|(path, entry)| PyMemoryEntry::new(py, &path, entry.into()))
        .collect::<PyResult<_>>()?;
    Ok(PyMemoryExtraction {
        report: PyExtractionReport::from(report),
        entries,
    })
}

/// The result of [`create_archive_to_bytes`].
///
/// # Attributes
///
/// * `data` - The archive bytes
/// * `report` - The `CreationReport`
#[pyclass(name = "CreatedArchive", frozen)]
pub struct PyCreatedArchive {
    data: Py<PyBytes>,
    report: PyCreationReport,
}

#[pymethods]
impl PyCreatedArchive {
    #[getter]
    fn data(&self, py: Python<'_>) -> Py<PyBytes> {
        self.data.clone_ref(py)
    }

    #[getter]
    fn report(&self) -> PyCreationReport {
        self.report.clone()
    }
}

/// Create an archive from source files and directories into memory.
///
/// The whole archive is held in memory (about 2-3x its size at the peak) with
/// no size cap, so use `create_archive` for large archives. Sources must be
/// regular files and directories; FIFOs and device files are not supported.
///
/// # Arguments
///
/// * `sources` - List of source files/directories to include (str or
///   pathlib.Path)
/// * `format` - One of `"Tar"`, `"TarGz"`, `"TarBz2"`, `"TarXz"`, `"TarZst"` or
///   `"Zip"`; `"SevenZ"` cannot be created
/// * `config` - Optional `CreationConfig` (uses defaults if None)
///
/// # Returns
///
/// `CreatedArchive` with the archive bytes and the report
///
/// # Raises
///
/// * `ValueError` - Unknown `format`, invalid sources, or `"SevenZ"`
/// * `IOError` - A source cannot be read
///
/// # Examples
///
/// ```python
/// from exarch import create_archive_to_bytes
///
/// created = create_archive_to_bytes(["src/"], "TarGz")
/// print(len(created.data), created.report.files_added)
/// ```
#[pyfunction]
#[pyo3(signature = (sources, format, config=None))]
pub fn create_archive_to_bytes(
    py: Python<'_>,
    sources: &Bound<'_, PyAny>,
    format: &str,
    config: Option<PyRef<'_, PyCreationConfig>>,
) -> PyResult<PyCreatedArchive> {
    let format = parse_creatable_format(format)?;
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<exarch_core::BoundaryPath> = sources_list
        .iter()
        .map(|source| path_to_boundary(py, source))
        .collect::<PyResult<_>>()?;
    let config = PyCreationConfig::snapshot(config);

    let (bytes, report) = catch_panic_as_py_err("archive creation", || {
        py.detach(|| CreateRequest::new(&config).to_bytes(format, &source_paths))
    })?;

    Ok(PyCreatedArchive {
        data: PyBytes::new(py, &bytes).unbind(),
        report: PyCreationReport::from(report),
    })
}

/// List the contents of an archive held in memory, without extracting.
///
/// # Arguments
///
/// * `data` - The archive bytes (`bytes`, or any object that converts to it)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `ListOptions`, as in `list_archive`
/// * `format` - The archive format (`"Tar"`, `"TarGz"`, `"TarBz2"`, `"TarXz"`,
///   `"TarZst"`, `"Zip"`, `"SevenZ"`); detected from the leading bytes if None
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Raises
///
/// * `ValueError` - Unknown `format`
/// * `UnknownFormatError` - The format cannot be detected from the bytes
/// * `UnsupportedFormatError` - Archive format not supported
/// * `InvalidArchiveError` - Archive is corrupted
///
/// # Examples
///
/// ```python
/// from exarch import list_archive_bytes
///
/// with open("archive.tar.gz", "rb") as f:
///     manifest = list_archive_bytes(f.read())
/// ```
#[pyfunction]
#[pyo3(signature = (data, config=None, options=None, format=None))]
pub fn list_archive_bytes(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyListOptions>>,
    format: Option<&str>,
) -> PyResult<PyArchiveManifest> {
    let format = parse_format(format)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyListOptions::snapshot(options);

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive listing", || {
        py.detach(|| {
            let reader = data.into_reader(format)?;
            ListRequest::new(&config)
                .with_options(options)
                .list_reader(reader)
                .map(|manifest| {
                    PyArchiveManifest::new(manifest, &config, VolumeIdentity::default())
                })
        })
    });
    slot.surface(result)
}

/// Verify the security of an archive held in memory.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if None
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Raises
///
/// The exceptions of `list_archive_bytes`.
///
/// # Examples
///
/// ```python
/// from exarch import verify_archive_bytes
///
/// with open("archive.zip", "rb") as f:
///     report = verify_archive_bytes(f.read())
/// print(report.is_safe)
/// ```
#[pyfunction]
#[pyo3(signature = (data, config=None, options=None, format=None))]
pub fn verify_archive_bytes(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyVerificationOptions>>,
    format: Option<&str>,
) -> PyResult<PyVerificationReport> {
    let format = parse_format(format)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyVerificationOptions::snapshot(options);

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive verification", || {
        py.detach(|| {
            let reader = data.into_reader(format)?;
            VerifyRequest::new(&config)
                .with_options(options)
                .verify_reader(reader)
        })
    });
    let report = slot.surface(result)?;

    Ok(PyVerificationReport::from(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_entry_kind_spellings_match_the_stub() {
        let pyi = include_str!("../exarch.pyi");
        let values: Vec<String> = MemoryEntryKind::ALL
            .iter()
            .map(|kind| format!("\"{}\"", kind.as_str()))
            .collect();
        let line = format!("_MemoryEntryKind = Literal[{}]", values.join(", "));
        assert!(pyi.lines().any(|l| l == line), "missing stub line: {line}");
    }
}
