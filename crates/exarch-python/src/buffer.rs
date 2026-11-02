//! Archives held in memory instead of on disk.

use std::num::NonZeroU64;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::CallbackSink;
use exarch_core::MemoryEntry;
use exarch_core::MemoryEntryKind;
use exarch_core::MemoryExtractRequest;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PartialWrites;
use exarch_core::PathModel;
use exarch_core::SafePath;
use exarch_core::SanitizedMode;
use exarch_core::extract_reader_to_memory;
use exarch_core::formats::detect::ArchiveType;
use exarch_core::formats::detect::CreatableFormat;
use pyo3::exceptions::PyRuntimeError;
use pyo3::exceptions::PyTypeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::PyProgressAdapter;
use crate::catch_panic_as_py_err;
use crate::catch_panic_as_py_result;
use crate::config::PyCreationConfig;
use crate::config::PyExtractionOptions;
use crate::config::PySecurityConfig;
use crate::config::PyVerificationOptions;
use crate::error::convert_error;
use crate::merge_progress_result;
use crate::path_to_string;
use crate::report::PyArchiveManifest;
use crate::report::PyCreationReport;
use crate::report::PyExtractionReport;
use crate::report::PyVerificationReport;
use crate::stream::ArchiveInput;

/// Parses the string form of a closed core enum (`ALL` and `as_str`).
fn parse_one<T: Copy>(
    what: &str,
    all: &[T],
    as_str: fn(T) -> &'static str,
    value: &str,
) -> PyResult<T> {
    all.iter()
        .copied()
        .find(|variant| as_str(*variant) == value)
        .ok_or_else(|| {
            let allowed: Vec<_> = all.iter().map(|variant| as_str(*variant)).collect();
            PyValueError::new_err(format!(
                "{what} must be one of {}, got {value:?}",
                allowed.join(", ")
            ))
        })
}

/// Parses an optional string form of a closed core enum.
fn parse_variant<T: Copy>(
    what: &str,
    all: &[T],
    as_str: fn(T) -> &'static str,
    value: Option<&str>,
) -> PyResult<Option<T>> {
    value
        .map(|value| parse_one(what, all, as_str, value))
        .transpose()
}

/// Parses the string form shared with `ArchiveType::as_str`.
fn parse_format(format: Option<&str>) -> PyResult<Option<ArchiveType>> {
    parse_variant("format", ArchiveType::ALL, ArchiveType::as_str, format)
}

/// Parses the string form shared with `PathModel::as_str`.
fn parse_path_model(path_model: Option<&str>) -> PyResult<Option<PathModel>> {
    parse_variant("path_model", PathModel::ALL, PathModel::as_str, path_model)
}

/// An entry extracted into memory.
///
/// # Attributes
///
/// * `path` - Entry path, relative, as delivered by extraction
/// * `kind` - `"file"`, `"directory"`, `"symlink"` or `"hardlink"` (the last
///   only from `extract_archive_to_callback`)
/// * `data` - The file's bytes (`None` unless `kind` is `"file"`)
/// * `mode` - Permission bits after setuid and setgid were stripped (`None`
///   unless a file whose archive carries a mode)
/// * `target` - For `"symlink"`, the target as the archive spells it, relative
///   to the link; for `"hardlink"`, the root-relative resolved path of an
///   already delivered entry, a file or an earlier hardlink (`None` for other
///   kinds)
#[pyclass(name = "MemoryEntry", frozen)]
pub struct PyMemoryEntry {
    path: String,
    kind: MemoryEntryKind,
    data: Option<Py<PyBytes>>,
    mode: Option<u32>,
    target: Option<String>,
}

#[pymethods]
impl PyMemoryEntry {
    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    #[getter]
    fn kind(&self) -> &'static str {
        self.kind.as_str()
    }

    #[getter]
    fn data(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.data.as_ref().map(|data| data.clone_ref(py))
    }

    #[getter]
    fn mode(&self) -> Option<u32> {
        self.mode
    }

    #[getter]
    fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "MemoryEntry(path={:?}, kind={:?})",
            self.path,
            self.kind.as_str()
        )
    }
}

impl PyMemoryEntry {
    fn new(py: Python<'_>, path: &Path, entry: MemoryEntry) -> PyResult<Self> {
        let path = utf8(path)?;
        let kind = entry.kind();
        let (data, mode, target) = match entry {
            MemoryEntry::File { data, mode } => (
                Some(PyBytes::new(py, &data).unbind()),
                mode.map(SanitizedMode::as_u32),
                None,
            ),
            MemoryEntry::Symlink { target } | MemoryEntry::Hardlink { target } => {
                (None, None, Some(utf8(&target)?))
            }
            MemoryEntry::Directory => (None, None, None),
            _ => {
                return Err(PyRuntimeError::new_err(
                    "exarch-python is older than exarch-core: unknown memory entry kind",
                ));
            }
        };
        Ok(Self {
            path,
            kind,
            data,
            mode,
            target,
        })
    }
}

/// The text of `path`, or an error: a lossy conversion could merge two
/// distinct entries into one name.
fn utf8(path: &Path) -> PyResult<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        convert_error(ArchiveError::InvalidArchive(format!(
            "entry path is not valid UTF-8: {}",
            path.display()
        )))
    })
}

/// Validates `max_bytes`: a positive count that fits in 64 bits.
fn parse_max_bytes(max_bytes: Option<i128>) -> PyResult<Option<NonZeroU64>> {
    max_bytes
        .map(|bytes| {
            u64::try_from(bytes)
                .ok()
                .and_then(NonZeroU64::new)
                .ok_or_else(|| {
                    convert_error(ArchiveError::InvalidConfiguration {
                        reason: "max_bytes must be a positive whole number of bytes".into(),
                    })
                })
        })
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
/// * `options` - Optional `ExtractionOptions` (`atomic` is not supported)
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
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, config=None, options=None, max_bytes=None, path_model=None, format=None))]
pub fn extract_archive_to_memory(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    options: Option<&PyExtractionOptions>,
    max_bytes: Option<i128>,
    path_model: Option<String>,
    format: Option<String>,
) -> PyResult<PyMemoryExtraction> {
    let request = MemoryRequest::parse(
        config,
        options,
        max_bytes,
        path_model.as_deref(),
        format.as_deref(),
    )?;

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
/// * `progress` - Optional progress callback function
/// * `options` - Optional `ExtractionOptions` (`atomic` is not supported)
/// * `max_bytes` - See `extract_archive_to_memory`
/// * `path_model` - See `extract_archive_to_memory`
/// * `format` - The archive format; detected from the leading bytes if None
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
/// Extraction runs to completion; a raising `progress` cannot abort it, and is
/// not called again once it has raised.
///
/// - If extraction succeeds, the callback's exception is raised and the
///   extracted entries are discarded, because nothing was written to disk. A
///   `writes = "discarded"` attribute and a `progress_callback_error = True`
///   marker are attached to it; it carries no counters.
/// - If extraction fails, the core error takes priority and the callback's
///   exception is chained onto it via `__cause__`.
///
/// The GIL is held during extraction when `progress` is given.
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
///     result = extract_archive_to_memory_with_progress(f.read(), None, progress)
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    reason = "pyo3 cannot extract `&str` under abi3-py39; the signature mirrors the sibling function"
)]
#[pyo3(signature = (data, config=None, progress=None, options=None, max_bytes=None, path_model=None, format=None))]
pub fn extract_archive_to_memory_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    progress: Option<Py<PyAny>>,
    options: Option<&PyExtractionOptions>,
    max_bytes: Option<i128>,
    path_model: Option<String>,
    format: Option<String>,
) -> PyResult<PyMemoryExtraction> {
    let request = MemoryRequest::parse(
        config,
        options,
        max_bytes,
        path_model.as_deref(),
        format.as_deref(),
    )?;

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

/// Runs `run` with the Python callback `progress`, holding the GIL, or with the
/// GIL released and a no-op reporter when `progress` is absent.
///
/// A raising callback is merged with the result by `merge_progress_result`;
/// `attach` adds counters to the callback's exception when the run succeeded
/// (the successful value is discarded).
fn run_with_optional_progress<T: Send>(
    py: Python<'_>,
    context: &str,
    progress: Option<Py<PyAny>>,
    run: impl FnOnce(&mut dyn exarch_core::ProgressCallback) -> exarch_core::Result<T> + Send,
    attach: impl FnOnce(&Bound<'_, PyAny>, &T),
) -> PyResult<T> {
    match progress {
        None => catch_panic_as_py_err(context, || {
            py.detach(|| run(&mut exarch_core::NoopProgress))
        }),
        Some(callback) => {
            let mut adapter = PyProgressAdapter::new(callback);
            let result = catch_panic_as_py_result(context, || Ok(run(&mut adapter)))?;
            merge_progress_result(py, result, adapter.into_callback_error(), attach)
        }
    }
}

/// List the contents of an archive held in memory, with a progress callback.
///
/// Same as `list_archive_bytes`, plus `progress`, called once per entry with
/// `(path: str, total: int, current: int, bytes_written: int)`. `total` is 0
/// for TAR, and `bytes_written` is always 0.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `progress` - Optional progress callback function
/// * `format` - The archive format; detected from the leading bytes if None
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Raises
///
/// * The exceptions of `list_archive_bytes`
/// * Whatever `progress` itself raises: listing runs to completion, and if it
///   succeeded the callback's exception is raised and the manifest discarded,
///   with a `progress_callback_error = True` marker. If listing failed, the
///   core error is raised with the callback's exception as `__cause__`.
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
///     manifest = list_archive_bytes_with_progress(f.read(), None, progress)
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, config=None, progress=None, format=None))]
pub fn list_archive_bytes_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    progress: Option<Py<PyAny>>,
    format: Option<String>,
) -> PyResult<PyArchiveManifest> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = exarch_core::ListOptions::default();

    let slot = data.failure_slot();
    let result = run_with_optional_progress(
        py,
        "archive listing with progress",
        progress,
        |progress| {
            let reader = data.into_reader(format)?;
            exarch_core::list_reader_with_progress(reader, config_ref, &options, progress)
        },
        |_, _| {},
    );
    let manifest = slot.surface(result)?;

    Ok(PyArchiveManifest::from(manifest))
}

/// Verify the security of an archive held in memory, with a progress callback.
///
/// Same as `verify_archive_bytes`, plus `progress`, called once per entry with
/// `(path: str, total: int, current: int, bytes_written: int)`. `total` is 0
/// for TAR, and `bytes_written` is always 0.
///
/// # Arguments
///
/// * `data` - The archive bytes
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `progress` - Optional progress callback function
/// * `options` - Optional `VerificationOptions`
/// * `format` - The archive format; detected from the leading bytes if None
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Raises
///
/// * The exceptions of `verify_archive_bytes`
/// * Whatever `progress` itself raises: if verification returned a report
///   (including a failing one), the callback's exception is raised and the
///   report discarded, with a `progress_callback_error = True` marker. If it
///   errored, the core error is raised with the callback's exception as
///   `__cause__`.
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
///     report = verify_archive_bytes_with_progress(f.read(), None, progress)
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, config=None, progress=None, options=None, format=None))]
pub fn verify_archive_bytes_with_progress(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    progress: Option<Py<PyAny>>,
    options: Option<&PyVerificationOptions>,
    format: Option<String>,
) -> PyResult<PyVerificationReport> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    let slot = data.failure_slot();
    let result = run_with_optional_progress(
        py,
        "archive verification with progress",
        progress,
        |progress| {
            let reader = data.into_reader(format)?;
            exarch_core::verify_reader_with_progress(reader, config_ref, options_ref, progress)
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
/// * `options` - Optional `ExtractionOptions` (`atomic` is not supported)
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
/// returned. The size of a file is checked, but a stream-level checksum is not:
/// the gzip CRC of a `.tar.gz` is never checked on extraction, so a corrupt
/// compressed stream can deliver altered data without an error.
///
/// # Entry kinds
///
/// A `"symlink"` entry's `target` is spelled as the archive stores it, relative
/// to the link. A `"hardlink"` entry is delivered by reference, after every
/// other entry: its `target` is the root-relative resolved path of an entry
/// that was already delivered, a file or an earlier hardlink (a chain is
/// delivered link by link), and no bytes are repeated. With
/// `ExtractionOptions().with_skip_duplicates(False)` one path can be
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
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, on_entry, config=None, options=None, path_model=None, format=None))]
pub fn extract_archive_to_callback(
    py: Python<'_>,
    data: ArchiveInput,
    on_entry: Py<PyAny>,
    config: Option<&PySecurityConfig>,
    options: Option<&PyExtractionOptions>,
    path_model: Option<String>,
    format: Option<String>,
) -> PyResult<PyExtractionReport> {
    if !on_entry.bind(py).is_callable() {
        return Err(PyTypeError::new_err("on_entry must be callable"));
    }
    let request = MemoryRequest::parse(
        config,
        options,
        None,
        path_model.as_deref(),
        format.as_deref(),
    )?;

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive extraction to a callback", || {
        py.detach(|| {
            let mut sink = CallbackSink::new(|path: &SafePath, entry| {
                Python::attach(|py| {
                    let entry = PyMemoryEntry::new(py, path.as_path(), entry)
                        .and_then(|entry| Py::new(py, entry))?;
                    on_entry.call1(py, (entry,)).map(drop)
                })
                .map_err(|err| slot.record(err))
            })
            .with_path_model(request.path_model);
            let reader = data.into_reader(request.format)?;
            exarch_core::extract_to_sink_with_progress(
                reader,
                &mut sink,
                &request.config,
                &request.options,
                &mut exarch_core::NoopProgress,
            )
        })
    });
    slot.surface(result).map(PyExtractionReport::from)
}

/// The validated arguments shared by the in-memory extraction functions.
struct MemoryRequest {
    request: MemoryExtractRequest,
    config: exarch_core::SecurityConfig,
    options: exarch_core::SinkOptions,
    path_model: PathModel,
    format: Option<ArchiveType>,
}

impl MemoryRequest {
    fn parse(
        config: Option<&PySecurityConfig>,
        options: Option<&PyExtractionOptions>,
        max_bytes: Option<i128>,
        path_model: Option<&str>,
        format: Option<&str>,
    ) -> PyResult<Self> {
        let format = parse_format(format)?;
        let path_model = parse_path_model(path_model)?.unwrap_or_default();
        let max_bytes = parse_max_bytes(max_bytes)?;
        let config = config.map_or_else(exarch_core::SecurityConfig::default, |c| {
            c.as_core().clone()
        });
        let options = options
            .map_or_else(
                || Ok(exarch_core::SinkOptions::default()),
                |o| exarch_core::SinkOptions::try_from(o.as_core()),
            )
            .map_err(convert_error)?;
        let mut request = MemoryExtractRequest::default()
            .with_config(config.clone())
            .with_options(options)
            .with_path_model(path_model);
        if let Some(bytes) = max_bytes {
            request = request.with_limit(MemoryLimit::new(bytes));
        }
        Ok(Self {
            request,
            config,
            options,
            path_model,
            format,
        })
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
        .map(|(path, entry)| Py::new(py, PyMemoryEntry::new(py, &path, entry)?))
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
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (sources, format, config=None))]
pub fn create_archive_to_bytes(
    py: Python<'_>,
    sources: &Bound<'_, PyAny>,
    format: String,
    config: Option<&PyCreationConfig>,
) -> PyResult<PyCreatedArchive> {
    let format = parse_one("format", ArchiveType::ALL, ArchiveType::as_str, &format)?;
    let format = CreatableFormat::try_from(format).map_err(convert_error)?;
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<String> = sources_list
        .iter()
        .map(|source| path_to_string(py, source))
        .collect::<PyResult<_>>()?;
    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let (bytes, report) = catch_panic_as_py_err("archive creation", || {
        py.detach(|| exarch_core::create_to_bytes(&source_paths, format, config_ref))
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
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, config=None, format=None))]
pub fn list_archive_bytes(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    format: Option<String>,
) -> PyResult<PyArchiveManifest> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = exarch_core::ListOptions::default();

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive listing", || {
        py.detach(|| {
            let reader = data.into_reader(format)?;
            exarch_core::list_reader(reader, config_ref, &options)
        })
    });
    let manifest = slot.surface(result)?;

    Ok(PyArchiveManifest::from(manifest))
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
/// print(report.is_safe())
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (data, config=None, options=None, format=None))]
pub fn verify_archive_bytes(
    py: Python<'_>,
    data: ArchiveInput,
    config: Option<&PySecurityConfig>,
    options: Option<&PyVerificationOptions>,
    format: Option<String>,
) -> PyResult<PyVerificationReport> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    let slot = data.failure_slot();
    let result = catch_panic_as_py_err("archive verification", || {
        py.detach(|| {
            let reader = data.into_reader(format)?;
            exarch_core::verify_reader(reader, config_ref, options_ref)
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
