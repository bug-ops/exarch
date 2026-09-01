//! Python bindings for exarch-core.
//!
//! This module provides a Pythonic API for secure archive extraction with
//! built-in protection against path traversal, zip bombs, symlink attacks,
//! and other common vulnerabilities.

use pyo3::prelude::*;

mod config;
mod error;
mod report;

use config::PyCreationConfig;
use config::PyExtractionOptions;
use config::PySecurityConfig;
use error::convert_error;
use error::register_exceptions;
use report::PyArchiveEntry;
use report::PyArchiveManifest;
use report::PyCreationReport;
use report::PyExtractionReport;
use report::PyVerificationIssue;
use report::PyVerificationReport;

// The `catch_unwind` guards throughout this module only convert Rust panics
// into `PyRuntimeError` when the crate is built with `panic = "unwind"`;
// under `panic = "abort"` they are dead code and the whole Python process
// aborts on any panic. Fail the build loudly instead of silently
// reintroducing that vulnerability (see issue #395).
const _: () = assert!(
    cfg!(panic = "unwind"),
    "exarch-python must be built with panic=unwind so catch_unwind can convert Rust panics into catchable Python exceptions; see issue #395"
);

/// Extract an archive to the specified directory.
///
/// This function provides secure archive extraction with configurable
/// security policies. By default, it uses a restrictive security
/// configuration that blocks symlinks, hardlinks, absolute paths, and
/// enforces resource quotas.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file (str or pathlib.Path)
/// * `output_dir` - Directory where files will be extracted (str or
///   pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Raises
///
/// * `ValueError` - Invalid argument type
/// * `PathTraversalError` - Path traversal attempt detected
/// * `SymlinkEscapeError` - Symlink points outside extraction directory
/// * `HardlinkEscapeError` - Hardlink target outside extraction directory
/// * `ZipBombError` - Potential zip bomb detected
/// * `InvalidPermissionsError` - File permissions are invalid or unsafe
/// * `QuotaExceededError` - Resource quota exceeded
/// * `SecurityViolationError` - Security policy violation
/// * `UnsupportedFormatError` - Archive format not supported
/// * `InvalidArchiveError` - Archive is corrupted
/// * `IOError` - I/O operation failed
///
/// # Security Considerations
///
/// ## GIL Release and TOCTOU
///
/// The GIL is released during extraction for performance. This creates a
/// Time-Of-Check-Time-Of-Use (TOCTOU) race condition where the archive file
/// could be modified between validation and extraction. This is an accepted
/// tradeoff for performance. For untrusted archives, ensure exclusive access
/// to the archive file during extraction.
///
/// ## Input Validation
///
/// - Paths containing null bytes are rejected (security)
/// - Paths exceeding 4096 bytes are rejected (`DoS` prevention)
/// - All validation happens at the Python boundary before calling core library
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive, SecurityConfig, ExtractionOptions
/// from pathlib import Path
///
/// # Use secure defaults with string paths
/// report = extract_archive("archive.tar.gz", "/tmp/output")
/// print(f"Extracted {report.files_extracted} files")
///
/// # Use pathlib.Path objects
/// archive = Path("archive.tar.gz")
/// output = Path("/tmp/output")
/// report = extract_archive(archive, output)
///
/// # Customize security settings
/// config = SecurityConfig().max_file_size(100 * 1024 * 1024)
/// report = extract_archive("archive.tar.gz", "/tmp/output", config)
///
/// # Customize extraction options
/// opts = ExtractionOptions().with_skip_duplicates(False)
/// report = extract_archive("archive.tar.gz", "/tmp/output", None, opts)
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, output_dir, config=None, options=None))]
fn extract_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    output_dir: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
    options: Option<&PyExtractionOptions>,
) -> PyResult<PyExtractionReport> {
    // Convert Path-like objects to strings
    let archive_path = path_to_string(py, archive_path)?;
    let output_dir = path_to_string(py, output_dir)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let default_options = exarch_core::ExtractionOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    // Release GIL during I/O-heavy extraction
    // NOTE: TOCTOU race condition - archive contents can change between check
    // and extraction. This is an accepted limitation when releasing the GIL
    // for performance.
    let report = catch_panic_as_py_err("extraction", || {
        py.detach(|| {
            exarch_core::extract_archive_with_options(
                &archive_path,
                &output_dir,
                config_ref,
                options_ref,
            )
        })
    })?;

    Ok(PyExtractionReport::from(report))
}

/// Converts a Path-like object to a string with validation.
///
/// Accepts both strings and `pathlib.Path` objects by calling `os.fspath()`.
///
/// # Security
///
/// Delegates to the shared boundary check in `exarch_core`; see
/// [`exarch_core::validate_raw_path_str`] for the exact rules (null bytes,
/// maximum length). Errors are routed through [`convert_error`] so they
/// surface as `SecurityViolationError`, the same exception type used for
/// every other security-policy rejection raised by this module.
fn path_to_string(py: Python<'_>, path: &Bound<'_, PyAny>) -> PyResult<String> {
    // Try direct string extraction first
    let path_str = if let Ok(s) = path.extract::<String>() {
        s
    } else {
        // Try os.fspath() for Path objects
        let os = py.import("os")?;
        let fspath = os.getattr("fspath")?;
        let result = fspath.call1((path,))?;
        result.extract()?
    };

    exarch_core::validate_raw_path_str(&path_str).map_err(convert_error)?;

    Ok(path_str)
}

/// Runs `f`, converting a Rust panic into a `PyRuntimeError` instead of
/// letting it unwind across the FFI boundary (see issue #395).
///
/// `context` is interpolated into the error message as "Internal panic
/// during {context}".
fn catch_panic_as_py_err<T>(
    context: &str,
    f: impl FnOnce() -> exarch_core::Result<T>,
) -> PyResult<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Internal panic during {context}"
            ))
        })?
        .map_err(convert_error)
}

/// Catches a panic inside `f` and converts it into `PyRuntimeError`, without
/// any further error mapping.
///
/// Unlike [`catch_panic_as_py_err`], `f` already returns a fully-formed
/// `PyResult`. Used by the `*_with_progress` entry points, where a raising
/// progress callback produces a `PyErr` directly — one that [`convert_error`]
/// (which only maps `exarch_core::ArchiveError`) cannot express.
fn catch_panic_as_py_result<T>(context: &str, f: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Internal panic during {context}"
        ))
    })?
}

/// Deliberately panics inside [`catch_panic_as_py_err`] so the panic ->
/// `PyRuntimeError` conversion can be verified end-to-end through the real
/// Python API surface (see issue #395's regression-test requirement).
///
/// Only present when the crate is built with the `panic-injection` feature,
/// which is never enabled for published wheels.
#[cfg(feature = "panic-injection")]
#[pyfunction]
fn _trigger_panic_for_testing() -> PyResult<()> {
    catch_panic_as_py_err("test operation (panic-injection)", || {
        panic!("deliberate panic from _trigger_panic_for_testing (issue #395 regression test)")
    })
}

/// Create an archive from source files and directories.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file (str or pathlib.Path)
/// * `sources` - List of source files/directories to include (str or
///   pathlib.Path)
/// * `config` - Optional `CreationConfig` (uses defaults if None)
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import create_archive, CreationConfig
///
/// # Use defaults
/// report = create_archive("output.tar.gz", ["source_dir/"])
/// print(f"Created archive with {report.files_added} files")
///
/// # Customize configuration
/// config = CreationConfig().compression_level(9)
/// report = create_archive("output.tar.gz", ["src/"], config)
/// ```
#[pyfunction]
#[pyo3(signature = (output_path, sources, config=None))]
fn create_archive(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<&PyCreationConfig>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_string(py, output_path)?;

    // Convert sources to Vec<String>
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<String> = sources_list
        .iter()
        .map(|s| path_to_string(py, s))
        .collect::<PyResult<_>>()?;

    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = catch_panic_as_py_err("archive creation", || {
        py.detach(|| exarch_core::create_archive(&output_path, &source_paths, config_ref))
    })?;

    Ok(PyCreationReport::from(report))
}

/// List archive contents without extracting.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file (str or pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import list_archive
///
/// manifest = list_archive("archive.tar.gz")
/// for entry in manifest.entries:
///     print(f"{entry.path}: {entry.size} bytes")
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, config=None))]
fn list_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
) -> PyResult<PyArchiveManifest> {
    let archive_path = path_to_string(py, archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let manifest = catch_panic_as_py_err("archive listing", || {
        py.detach(|| exarch_core::list_archive(&archive_path, config_ref))
    })?;

    Ok(PyArchiveManifest::from(manifest))
}

/// Verify archive integrity and security.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file (str or pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import verify_archive
///
/// report = verify_archive("archive.tar.gz")
/// if report.is_safe():
///     print("Archive is safe to extract")
/// else:
///     for issue in report.issues:
///         print(f"[{issue.severity}] {issue.message}")
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, config=None))]
fn verify_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
) -> PyResult<PyVerificationReport> {
    let archive_path = path_to_string(py, archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = catch_panic_as_py_err("archive verification", || {
        py.detach(|| exarch_core::verify_archive(&archive_path, config_ref))
    })?;

    Ok(PyVerificationReport::from(report))
}

/// Create an archive with progress callback.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file (str or pathlib.Path)
/// * `sources` - List of source files/directories to include (str or
///   pathlib.Path)
/// * `config` - Optional `CreationConfig` (uses defaults if None)
/// * `progress` - Optional progress callback function
///
/// Progress callback signature: `(path: str, total: int, current: int,
/// bytes_written: int) -> None`
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
/// * Whatever `progress` itself raises - see the note below
///
/// # A raising `progress` propagates instead of being swallowed
///
/// Creation has already run to completion (or failure) by the time the
/// exception is observed: the underlying `ProgressCallback` contract has no
/// cancellation signal, so a raising `progress` cannot abort creation early
/// (the same constraint documented on the Node binding's
/// `createArchiveWithProgress`, see issues #465/#485/#489). Once `progress`
/// raises, it is no longer called for the remaining entries.
///
/// - If creation otherwise succeeds, the callback's exception is what
///   propagates. `files_added` and `bytes_written` attributes describing what
///   was written are attached on a best-effort basis (`setattr` can fail, e.g.
///   for an exception class using `__slots__`), together with a
///   `progress_callback_error = True` marker attribute — check it before
///   assuming the mere presence of `files_added` means creation failed partway
///   through, matching the equivalent `extract_archive_with_progress` guidance
///   (`exarch_core` has no partial-creation error variant today, but the marker
///   keeps this call site consistent with the extraction side and correct if
///   that changes).
/// - If creation also fails, the core error takes priority (a raising callback
///   can never mask a security error such as `SymlinkEscapeError`) and the
///   callback's exception is chained onto it via `__cause__`. This error does
///   not carry the `progress_callback_error` marker.
///
/// # Examples
///
/// ```python
/// from exarch import create_archive_with_progress
///
/// def progress(path: str, total: int, current: int, bytes: int):
///     print(f"{current}/{total}: {path} ({bytes} bytes)")
///
/// report = create_archive_with_progress(
///     "output.tar.gz", ["src/"], None, progress
/// )
/// ```
#[pyfunction]
#[pyo3(signature = (output_path, sources, config=None, progress=None))]
fn create_archive_with_progress(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<&PyCreationConfig>,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_string(py, output_path)?;

    // Convert sources to Vec<String>
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<String> = sources_list
        .iter()
        .map(|s| path_to_string(py, s))
        .collect::<PyResult<_>>()?;

    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = catch_panic_as_py_result("archive creation with progress", || {
        run_create_with_optional_progress(py, &output_path, &source_paths, config_ref, progress)
    })?;

    Ok(PyCreationReport::from(report))
}

/// Runs `create_archive_with_progress` routed to the Python callback when
/// present, or with the GIL released and a no-op reporter when absent.
fn run_create_with_optional_progress(
    py: Python<'_>,
    output_path: &str,
    source_paths: &[String],
    config: &exarch_core::creation::CreationConfig,
    progress: Option<Py<PyAny>>,
) -> PyResult<exarch_core::creation::CreationReport> {
    progress.map_or_else(
        || {
            // No progress callback - can release GIL
            let mut noop = exarch_core::NoopProgress;
            py.detach(|| {
                exarch_core::create_archive_with_progress(
                    output_path,
                    source_paths,
                    config,
                    &mut noop,
                )
            })
            .map_err(convert_error)
        },
        |py_callback| {
            // CRITICAL: Do NOT release GIL when using Python callback!
            // Python callback requires GIL to call into Python.
            let mut callback = PyProgressAdapter::new(py_callback);
            let result = exarch_core::create_archive_with_progress(
                output_path,
                source_paths,
                config,
                &mut callback,
            );
            merge_progress_result(py, result, callback.into_callback_error(), |exc, report| {
                let _ = exc.setattr("files_added", report.files_added);
                let _ = exc.setattr("bytes_written", report.bytes_written);
            })
        },
    )
}

/// Merges a creation/extraction result with an exception captured from a
/// raising progress callback, mirroring the Node binding's
/// `ProgressCallbackError` semantics (see issues #465/#485): a core failure
/// always stays primary — the callback exception is chained onto it as
/// `__cause__` rather than masking it — while a callback exception over an
/// otherwise successful operation is raised directly.
///
/// `attach_report_attrs` attaches counters describing what was written
/// (`files_extracted`/`files_added` and `bytes_written`) onto the callback
/// exception in the success case; the attribute names differ between
/// extraction and creation, so the caller supplies them. In addition, a
/// `progress_callback_error = True` attribute is always attached alongside
/// them: without it, these counters are indistinguishable from the same two
/// attribute names [`convert_error`] attaches to a genuine
/// `PartialExtraction` (a core failure partway through), which would make a
/// caller following that documented `hasattr(e, "files_extracted")` idiom
/// misclassify a fully successful operation as a partial one (see #489
/// review). Attribute attachment is best-effort (`setattr` can fail, e.g. on
/// an exception class using `__slots__`); a failure here does not affect
/// which exception is raised.
fn merge_progress_result<T>(
    py: Python<'_>,
    result: exarch_core::Result<T>,
    callback_error: Option<PyErr>,
    attach_report_attrs: impl FnOnce(&Bound<'_, PyAny>, &T),
) -> PyResult<T> {
    match (result, callback_error) {
        (Ok(report), None) => Ok(report),
        (Ok(report), Some(err)) => {
            let exc_value = err.value(py);
            attach_report_attrs(exc_value, &report);
            let _ = exc_value.setattr("progress_callback_error", true);
            Err(err)
        }
        (Err(core_err), callback_err) => {
            let converted = convert_error(core_err);
            if let Some(cb_err) = callback_err {
                converted.set_cause(py, Some(cb_err));
            }
            Err(converted)
        }
    }
}

/// Extract an archive with progress callback.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file (str or pathlib.Path)
/// * `output_dir` - Directory where files will be extracted (str or
///   pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `progress` - Optional progress callback function
///
/// Progress callback signature: `(path: str, total: int, current: int,
/// bytes_written: int) -> None`
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `PathTraversalError` - Path traversal attempt detected
/// * `SymlinkEscapeError` - Symlink points outside extraction directory
/// * `HardlinkEscapeError` - Hardlink target outside extraction directory
/// * `ZipBombError` - Potential zip bomb detected
/// * `InvalidPermissionsError` - File permissions are invalid or unsafe
/// * `QuotaExceededError` - Resource quota exceeded
/// * `SecurityViolationError` - Security policy violation
/// * `UnsupportedFormatError` - Archive format not supported
/// * `InvalidArchiveError` - Archive is corrupted
/// * `IOError` - I/O operation failed
/// * Whatever `progress` itself raises - see the note below
///
/// # Security Considerations
///
/// ## GIL Release and TOCTOU
///
/// When a progress callback is provided the GIL is held during extraction so
/// that the callback can safely call into Python. Without a callback the GIL
/// is released for performance, but the TOCTOU caveat from `extract_archive`
/// still applies.
///
/// ## A raising `progress` propagates instead of being swallowed
///
/// Extraction has already run to completion (or failure) by the time the
/// exception is observed: the underlying `ProgressCallback` contract has no
/// cancellation signal, so a raising `progress` cannot abort extraction early
/// (the same constraint documented on the Node binding's
/// `extractArchiveWithProgress`, see issues #465/#485/#489). Once `progress`
/// raises, it is no longer called for the remaining entries.
///
/// - If extraction otherwise succeeds, the callback's exception is what
///   propagates. `files_extracted` and `bytes_written` attributes describing
///   what was written are attached on a best-effort basis (`setattr` can fail,
///   e.g. for an exception class using `__slots__`), together with a
///   `progress_callback_error = True` marker attribute. The marker exists
///   because `files_extracted`/`bytes_written` are the *same* attribute names a
///   genuine partial extraction carries (see `extract_archive`'s own
///   partial-extraction note) — check `progress_callback_error` first to tell
///   the two apart, rather than assuming their mere presence means extraction
///   failed partway through.
/// - If extraction also fails, the core error takes priority (a raising
///   callback can never mask a security error such as `SymlinkEscapeError`) and
///   the callback's exception is chained onto it via `__cause__`. This error
///   does not carry the `progress_callback_error` marker.
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive_with_progress
///
/// def progress(path: str, total: int, current: int, bytes: int):
///     print(f"{current}/{total}: {path} ({bytes} bytes)")
///
/// report = extract_archive_with_progress(
///     "archive.tar.gz", "/tmp/output", None, progress
/// )
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, output_dir, config=None, progress=None, options=None))]
fn extract_archive_with_progress(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    output_dir: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
    progress: Option<Py<PyAny>>,
    options: Option<&PyExtractionOptions>,
) -> PyResult<PyExtractionReport> {
    let archive_path = path_to_string(py, archive_path)?;
    let output_dir = path_to_string(py, output_dir)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let default_options = exarch_core::ExtractionOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    let report = catch_panic_as_py_result("archive extraction with progress", || {
        run_extract_with_optional_progress(
            py,
            &archive_path,
            &output_dir,
            config_ref,
            options_ref,
            progress,
        )
    })?;

    Ok(PyExtractionReport::from(report))
}

/// Runs `extract_archive_with_options_and_progress` routed to the Python
/// callback when present, or with the GIL released and a no-op reporter when
/// absent.
fn run_extract_with_optional_progress(
    py: Python<'_>,
    archive_path: &str,
    output_dir: &str,
    config: &exarch_core::SecurityConfig,
    options: &exarch_core::ExtractionOptions,
    progress: Option<Py<PyAny>>,
) -> PyResult<exarch_core::ExtractionReport> {
    progress.map_or_else(
        || {
            // No progress callback - can release GIL
            let mut noop = exarch_core::NoopProgress;
            py.detach(|| {
                exarch_core::extract_archive_with_options_and_progress(
                    archive_path,
                    output_dir,
                    config,
                    options,
                    &mut noop,
                )
            })
            .map_err(convert_error)
        },
        |py_callback| {
            // CRITICAL: Do NOT release GIL when using Python callback!
            // Python callback requires GIL to call into Python.
            let mut callback = PyProgressAdapter::new(py_callback);
            let result = exarch_core::extract_archive_with_options_and_progress(
                archive_path,
                output_dir,
                config,
                options,
                &mut callback,
            );
            merge_progress_result(py, result, callback.into_callback_error(), |exc, report| {
                let _ = exc.setattr("files_extracted", report.files_extracted);
                let _ = exc.setattr("bytes_written", report.bytes_written);
            })
        },
    )
}

/// Adapter that calls Python callback from Rust.
///
/// The Python callback receives `(path: str, total: int, current: int,
/// bytes_written: int)` where `bytes_written` is the number of bytes written
/// **for the current entry so far** (starts at 0 when the entry begins, grows
/// as chunks are flushed to disk).
///
/// If the callback raises, the exception is captured into `callback_error`
/// instead of being discarded (see issue #489). The
/// [`exarch_core::ProgressCallback`] contract has no cancellation signal —
/// the same constraint the Node binding documents for `NodeProgressAdapter`
/// (issues #465/#485) — so extraction/creation keeps running to completion;
/// once a raise has been captured, further dispatches are skipped, since
/// there is no value in repeatedly invoking a callback already known to be
/// broken. The caller retrieves the captured exception via
/// [`into_callback_error`](Self::into_callback_error) once the core
/// operation returns, and raises it to the Python caller.
struct PyProgressAdapter {
    callback: Py<PyAny>,
    current_entry_bytes: u64,
    callback_error: Option<PyErr>,
}

impl PyProgressAdapter {
    fn new(callback: Py<PyAny>) -> Self {
        Self {
            callback,
            current_entry_bytes: 0,
            callback_error: None,
        }
    }

    /// Consumes the adapter, returning the exception captured from a raising
    /// Python progress callback, if one occurred.
    fn into_callback_error(self) -> Option<PyErr> {
        self.callback_error
    }
}

impl exarch_core::ProgressCallback for PyProgressAdapter {
    fn on_entry_start(&mut self, path: &std::path::Path, total: usize, current: usize) {
        if self.callback_error.is_some() {
            return;
        }
        self.current_entry_bytes = 0;
        Python::attach(|py| {
            let path_str = path.to_string_lossy().into_owned();
            if let Err(err) = self
                .callback
                .call1(py, (path_str, total, current, self.current_entry_bytes))
            {
                self.callback_error = Some(err);
            }
        });
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.current_entry_bytes += bytes;
    }

    fn on_entry_complete(&mut self, _path: &std::path::Path) {
        // No-op: not exposed to Python (simplification)
    }

    fn on_complete(&mut self) {
        // No-op: Python can detect completion when function returns
    }
}

/// Python module definition.
#[pymodule]
fn exarch(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Module metadata
    m.add(
        "__doc__",
        "Memory-safe archive extraction library with security validation",
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Top-level functions
    m.add_function(wrap_pyfunction!(extract_archive, m)?)?;
    m.add_function(wrap_pyfunction!(extract_archive_with_progress, m)?)?;
    m.add_function(wrap_pyfunction!(create_archive, m)?)?;
    m.add_function(wrap_pyfunction!(create_archive_with_progress, m)?)?;
    m.add_function(wrap_pyfunction!(list_archive, m)?)?;
    m.add_function(wrap_pyfunction!(verify_archive, m)?)?;
    #[cfg(feature = "panic-injection")]
    m.add_function(wrap_pyfunction!(_trigger_panic_for_testing, m)?)?;

    // Configuration classes
    m.add_class::<PySecurityConfig>()?;
    m.add_class::<PyCreationConfig>()?;
    m.add_class::<PyExtractionOptions>()?;

    // Report classes
    m.add_class::<PyExtractionReport>()?;
    m.add_class::<PyCreationReport>()?;
    m.add_class::<PyArchiveManifest>()?;
    m.add_class::<PyArchiveEntry>()?;
    m.add_class::<PyVerificationReport>()?;
    m.add_class::<PyVerificationIssue>()?;

    // Exception types
    register_exceptions(m)?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;
    use exarch_core::MAX_PATH_LENGTH;
    use pyo3::types::PyString;

    #[test]
    fn test_module_metadata() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "test_exarch").expect("Failed to create module");
            let result = exarch(&module.as_borrowed());
            assert!(
                result.is_ok(),
                "Module initialization failed: {:?}",
                result.err()
            );

            // Verify module has __doc__ and __version__
            assert!(
                module.getattr("__doc__").is_ok(),
                "Module missing __doc__ attribute"
            );
            assert!(
                module.getattr("__version__").is_ok(),
                "Module missing __version__ attribute"
            );

            // Verify main function is registered
            assert!(
                module.getattr("extract_archive").is_ok(),
                "extract_archive function not registered"
            );

            // Verify classes are registered
            assert!(
                module.getattr("SecurityConfig").is_ok(),
                "SecurityConfig class not registered"
            );
            assert!(
                module.getattr("ExtractionReport").is_ok(),
                "ExtractionReport class not registered"
            );
        });
    }

    #[test]
    fn test_path_to_string_with_string() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test.tar.gz").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert string path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_string_empty() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert empty path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "");
        });
    }

    #[test]
    fn test_path_to_string_with_path_object() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let pathlib = py.import("pathlib").expect("Failed to import pathlib");
            let path_class = pathlib.getattr("Path").expect("Failed to get Path class");
            let path = path_class
                .call1(("/tmp/test.tar.gz",))
                .expect("Failed to create Path object");
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert Path object: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_string_rejects_null_bytes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test\0malicious.tar.gz").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(result.is_err(), "Should reject path with null bytes");
            let err_str = result.unwrap_err().to_string();
            assert!(
                err_str.contains("null bytes"),
                "Expected 'null bytes' in error, got: {}",
                err_str
            );
        });
    }

    #[test]
    fn test_path_to_string_rejects_too_long() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
            let path = PyString::new(py, &long_path).into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(result.is_err(), "Should reject excessively long path");
            let err_str = result.unwrap_err().to_string();
            assert!(
                err_str.contains("maximum length"),
                "Expected 'maximum length' in error, got: {}",
                err_str
            );
        });
    }

    #[test]
    fn test_path_to_string_accepts_max_length() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let max_path = "x".repeat(MAX_PATH_LENGTH);
            let path = PyString::new(py, &max_path).into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Should accept path at maximum length: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap().len(), MAX_PATH_LENGTH);
        });
    }

    /// Regression test for #489: a raising progress callback must stop being
    /// invoked for subsequent entries once its exception has been captured,
    /// mirroring `NodeProgressAdapter`'s equivalent behavior.
    #[test]
    fn test_progress_adapter_skips_dispatch_after_first_error() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let raiser = py
                .eval(
                    c"lambda *a: (_ for _ in ()).throw(RuntimeError('boom'))",
                    None,
                    None,
                )
                .expect("failed to build raising callback");
            let mut adapter = PyProgressAdapter::new(raiser.into());

            exarch_core::ProgressCallback::on_entry_start(
                &mut adapter,
                std::path::Path::new("first.txt"),
                2,
                1,
            );
            assert!(
                adapter.callback_error.is_some(),
                "first raise must be captured"
            );

            // A second dispatch after capture must be a no-op: if it weren't
            // skipped, invoking the same raising callback again is harmless
            // here, but a real callback might be expensive or bring
            // side-effects the contract requires not to repeat.
            exarch_core::ProgressCallback::on_entry_start(
                &mut adapter,
                std::path::Path::new("second.txt"),
                2,
                2,
            );

            let err = adapter
                .into_callback_error()
                .expect("captured exception must survive into_callback_error");
            assert!(
                err.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py),
                "expected RuntimeError, got: {err}"
            );
        });
    }

    /// Attaches `exarch_core::ExtractionReport` counters onto a callback
    /// exception, matching the closure passed to `merge_progress_result` at
    /// the real `extract_archive_with_progress` call site.
    fn attach_extraction_attrs(exc: &Bound<'_, PyAny>, report: &exarch_core::ExtractionReport) {
        let _ = exc.setattr("files_extracted", report.files_extracted);
        let _ = exc.setattr("bytes_written", report.bytes_written);
    }

    /// Attaches `exarch_core::creation::CreationReport` counters onto a
    /// callback exception, matching the closure passed to
    /// `merge_progress_result` at the real `create_archive_with_progress`
    /// call site.
    fn attach_creation_attrs(
        exc: &Bound<'_, PyAny>,
        report: &exarch_core::creation::CreationReport,
    ) {
        let _ = exc.setattr("files_added", report.files_added);
        let _ = exc.setattr("bytes_written", report.bytes_written);
    }

    /// Regression test for #489: when the core operation succeeds but the
    /// progress callback raised, the callback's exception must propagate
    /// (not be swallowed), carrying the report's counters as attributes plus
    /// the `progress_callback_error` marker (see #489 review S1) that
    /// distinguishes this case from a genuine `PartialExtraction`, which
    /// attaches the same `files_extracted`/`bytes_written` attribute names.
    #[test]
    fn test_merge_extraction_progress_result_callback_error_over_success() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let report = exarch_core::ExtractionReport {
                files_extracted: 3,
                bytes_written: 42,
                ..exarch_core::ExtractionReport::default()
            };
            let cb_err = PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("callback boom");

            let result =
                merge_progress_result(py, Ok(report), Some(cb_err), attach_extraction_attrs);

            let err = result.expect_err("callback exception must propagate");
            assert!(err.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py));
            let exc_value = err.value(py);
            let files: usize = exc_value
                .getattr("files_extracted")
                .expect("files_extracted missing")
                .extract()
                .expect("files_extracted not usize");
            let bytes: u64 = exc_value
                .getattr("bytes_written")
                .expect("bytes_written missing")
                .extract()
                .expect("bytes_written not u64");
            let marker: bool = exc_value
                .getattr("progress_callback_error")
                .expect("progress_callback_error missing")
                .extract()
                .expect("progress_callback_error not bool");
            assert_eq!(files, 3);
            assert_eq!(bytes, 42);
            assert!(marker, "progress_callback_error must be True");
        });
    }

    /// Regression test for #489: a core failure (e.g. a security violation)
    /// must stay the primary, specifically-typed exception even when the
    /// progress callback also raised — the callback exception is chained
    /// onto it via `__cause__` instead of masking it, and the success-path
    /// `progress_callback_error` marker must not be attached to it (a
    /// genuine `PartialExtraction` is distinguished from a callback-raise
    /// precisely by the marker's absence).
    #[test]
    fn test_merge_extraction_progress_result_core_error_takes_priority() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let core_err = exarch_core::ArchiveError::SymlinkEscape {
                path: std::path::PathBuf::from("/etc/passwd"),
            };
            let cb_err = PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("callback boom");

            let result =
                merge_progress_result(py, Err(core_err), Some(cb_err), attach_extraction_attrs);

            let err = result.expect_err("core error must propagate");
            assert!(
                err.is_instance_of::<error::SymlinkEscapeError>(py),
                "expected SymlinkEscapeError, got: {err}"
            );
            let cause = err.cause(py).expect("callback exception must be chained");
            assert!(cause.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py));
            assert!(
                !err.value(py)
                    .hasattr("progress_callback_error")
                    .unwrap_or(false),
                "core error must not carry the callback-over-success marker"
            );
        });
    }

    /// Regression test for #489: with no callback exception, a successful
    /// extraction result passes through unchanged.
    #[test]
    fn test_merge_extraction_progress_result_success_passthrough() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let report = exarch_core::ExtractionReport {
                files_extracted: 1,
                ..exarch_core::ExtractionReport::default()
            };
            let result = merge_progress_result(py, Ok(report), None, attach_extraction_attrs);
            assert_eq!(
                result
                    .expect("no callback error, no core error")
                    .files_extracted,
                1
            );
        });
    }

    /// Regression test for #489 (testing agent gap S3): the creation-side
    /// counterpart of
    /// `test_merge_extraction_progress_result_callback_error_over_success`.
    /// `merge_progress_result` is shared between extraction and creation, but
    /// the `files_added` attribute name is creation-specific and had zero
    /// coverage before this test.
    #[test]
    fn test_merge_creation_progress_result_callback_error_over_success() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let report = exarch_core::creation::CreationReport {
                files_added: 2,
                bytes_written: 17,
                ..exarch_core::creation::CreationReport::default()
            };
            let cb_err = PyErr::new::<pyo3::exceptions::PyValueError, _>("callback boom");

            let result = merge_progress_result(py, Ok(report), Some(cb_err), attach_creation_attrs);

            let err = result.expect_err("callback exception must propagate");
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
            let exc_value = err.value(py);
            let files: usize = exc_value
                .getattr("files_added")
                .expect("files_added missing")
                .extract()
                .expect("files_added not usize");
            let bytes: u64 = exc_value
                .getattr("bytes_written")
                .expect("bytes_written missing")
                .extract()
                .expect("bytes_written not u64");
            let marker: bool = exc_value
                .getattr("progress_callback_error")
                .expect("progress_callback_error missing")
                .extract()
                .expect("progress_callback_error not bool");
            assert_eq!(files, 2);
            assert_eq!(bytes, 17);
            assert!(marker, "progress_callback_error must be True");
        });
    }

    /// Regression test for #489 (testing agent gap S3): the creation-side
    /// counterpart of
    /// `test_merge_extraction_progress_result_core_error_takes_priority`.
    #[test]
    fn test_merge_creation_progress_result_core_error_takes_priority() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let core_err = exarch_core::ArchiveError::SourceNotFound {
                path: std::path::PathBuf::from("missing.txt"),
            };
            let cb_err = PyErr::new::<pyo3::exceptions::PyValueError, _>("callback boom");

            let result =
                merge_progress_result(py, Err(core_err), Some(cb_err), attach_creation_attrs);

            let err = result.expect_err("core error must propagate");
            assert!(err.is_instance_of::<pyo3::exceptions::PyIOError>(py));
            let cause = err.cause(py).expect("callback exception must be chained");
            assert!(cause.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    /// Regression test for #489 (testing agent gap S3): the creation-side
    /// counterpart of
    /// `test_merge_extraction_progress_result_success_passthrough`.
    #[test]
    fn test_merge_creation_progress_result_success_passthrough() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let report = exarch_core::creation::CreationReport {
                files_added: 1,
                ..exarch_core::creation::CreationReport::default()
            };
            let result = merge_progress_result(py, Ok(report), None, attach_creation_attrs);
            assert_eq!(
                result
                    .expect("no callback error, no core error")
                    .files_added,
                1
            );
        });
    }
}
