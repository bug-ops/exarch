//! Python bindings for exarch-core.
//!
//! This module provides a Pythonic API for secure archive extraction with
//! built-in protection against path traversal, zip bombs, symlink attacks,
//! and other common vulnerabilities.

use pyo3::prelude::*;
use std::ffi::OsString;
use std::path::Path;

mod buffer;
mod config;
mod error;
mod report;
mod stream;
mod warning;

use config::PyCreationConfig;
use config::PyExtractionOptions;
use config::PySecurityConfig;
use config::PyVerificationOptions;
use error::attach_partial;
use error::convert_error;
use error::register_exceptions;
use exarch_core::BoundaryPath;
use exarch_core::ConfigSetting;
use exarch_core::CreateRequest;
use exarch_core::Durability;
use exarch_core::ExtractRequest;
use exarch_core::ListRequest;
use exarch_core::OutputFile;
use exarch_core::VerifyRequest;
use report::PyArchiveEntry;
use report::PyArchiveManifest;
use report::PyCreationReport;
use report::PyExtractionReport;
use report::PyIntegrityGaps;
use report::PyUnverifiedEntry;
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
/// * `ZipInconsistencyError` - ZIP structure is read differently by different
///   tools (subclass of `SecurityViolationError`)
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
/// opts = ExtractionOptions().with_existing_files("overwrite")
/// report = extract_archive("archive.tar.gz", "/tmp/output", None, opts)
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, output_dir, config=None, options=None))]
fn extract_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    output_dir: &Bound<'_, PyAny>,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyExtractionOptions>>,
) -> PyResult<PyExtractionReport> {
    let archive_path = path_to_boundary(py, archive_path)?;
    let output_dir = path_to_boundary(py, output_dir)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyExtractionOptions::snapshot(options);

    // Release GIL during I/O-heavy extraction
    // NOTE: TOCTOU race condition - archive contents can change between check
    // and extraction. This is an accepted limitation when releasing the GIL
    // for performance.
    let report = catch_panic_as_py_err("extraction", || {
        py.detach(|| {
            ExtractRequest::new(&config)
                .with_options(options)
                .extract(&archive_path, &output_dir)
        })
    })?;

    Ok(PyExtractionReport::from(report))
}

/// Converts a Path-like object to a validated host path.
///
/// Accepts `str`, `bytes` and `os.PathLike` objects through `os.fsdecode`, and
/// reads the result back as the exact bytes of the host path, so a path that is
/// not valid UTF-8 (a surrogate-escaped `str` or a `bytes` path) reaches core
/// unchanged instead of failing with an untyped `UnicodeEncodeError`.
///
/// # Security
///
/// Delegates to the shared boundary check in `exarch_core`; see
/// [`exarch_core::BoundaryPath::parse_os`] for the exact rules (null bytes,
/// maximum length). Errors are routed through [`convert_error`] so they
/// surface as `SecurityViolationError`, the same exception type used for
/// every other security-policy rejection raised by this module.
fn path_to_boundary(py: Python<'_>, path: &Bound<'_, PyAny>) -> PyResult<BoundaryPath> {
    let decoded = py.import("os")?.call_method1("fsdecode", (path,))?;
    BoundaryPath::parse_os(decoded.extract::<OsString>()?).map_err(convert_error)
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
/// * `format` - The format to write whatever the extension is (for example
///   `"Zip"` for a `.whl`); `None` detects it from the extension
/// * `overwrite` - Replace an existing regular file or symlink, keeping its
///   permission bits (default); `False` refuses any existing output
/// * `durability` - `"synced"` (default) flushes the archive and its directory
///   entry before returning; `"unsynced"` skips both, which is faster but after
///   a crash or power loss a replaced output can be empty or truncated and a
///   new output can be empty, and write-back errors (network filesystems,
///   quotas, delayed allocation) are not reported
///
/// The archive is written to a temporary file next to `output_path` (whose
/// directory must be writable) and renamed into place when complete, so a
/// failed creation leaves `output_path` as it was. The output and its
/// temporary file are never archived, even inside a source directory.
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Raises
///
/// * `OutputExistsError` - `overwrite` is `False` and `output_path` exists
/// * `InvalidConfigurationError` - `output_path` is a directory, FIFO or device
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
/// config = CreationConfig().with_compression_level(9)
/// report = create_archive("output.tar.gz", ["src/"], config)
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    reason = "pyo3 cannot extract `&str` under abi3-py39"
)]
#[pyo3(signature = (output_path, sources, config=None, format=None, overwrite=true, durability=None))]
fn create_archive(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<PyRef<'_, PyCreationConfig>>,
    format: Option<String>,
    overwrite: bool,
    durability: Option<String>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_boundary(py, output_path)?;
    let source_paths = source_boundary_paths(py, sources)?;
    let config = PyCreationConfig::snapshot(config);
    let output = output_file(
        &output_path,
        overwrite,
        format.as_deref(),
        durability.as_deref(),
    )?;

    let report = catch_panic_as_py_err("archive creation", || {
        py.detach(|| CreateRequest::new(&config).create(&output, &source_paths))
    })?;

    Ok(PyCreationReport::from(report))
}

/// Validates every creation source path.
pub(crate) fn source_boundary_paths(
    py: Python<'_>,
    sources: &Bound<'_, PyAny>,
) -> PyResult<Vec<BoundaryPath>> {
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    sources_list
        .iter()
        .map(|source| path_to_boundary(py, source))
        .collect()
}

/// The output file of a creation: replaced or refused when it exists, in the
/// stated format or the one its extension names, flushed or not.
fn output_file(
    path: &BoundaryPath,
    overwrite: bool,
    format: Option<&str>,
    durability: Option<&str>,
) -> PyResult<OutputFile> {
    let path = AsRef::<Path>::as_ref(path).to_path_buf();
    let output = if overwrite {
        OutputFile::replace(path)
    } else {
        OutputFile::create_new(path)
    };
    let output = match format {
        Some(format) => output.with_format(buffer::parse_creatable_format(format)?),
        None => output,
    };
    let durability = durability
        .map(|value| buffer::parse_one::<Durability>(ConfigSetting::Durability, value))
        .transpose()?
        .unwrap_or_default();
    Ok(output.with_durability(durability))
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
    config: Option<PyRef<'_, PySecurityConfig>>,
) -> PyResult<PyArchiveManifest> {
    let archive_path = path_to_boundary(py, archive_path)?;
    let config = PySecurityConfig::snapshot(config);

    let manifest = catch_panic_as_py_err("archive listing", || {
        py.detach(|| ListRequest::new(&config).list(&archive_path))
    })?;

    Ok(PyArchiveManifest::from(manifest))
}

/// Verify archive security.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file (str or pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
/// * `options` - Optional `VerificationOptions`; pass
///   `VerificationOptions().with_integrity_check()` to decode the payload and
///   verify checksums (default: metadata only, `integrity_status` is
///   `"SKIPPED"`)
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
/// * `InvalidArchiveError` - With the integrity check on, a TAR entry whose
///   content fails to decode (a resource limit or I/O failure while decoding
///   raises its own typed error)
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
#[pyo3(signature = (archive_path, config=None, options=None))]
fn verify_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    config: Option<PyRef<'_, PySecurityConfig>>,
    options: Option<PyRef<'_, PyVerificationOptions>>,
) -> PyResult<PyVerificationReport> {
    let archive_path = path_to_boundary(py, archive_path)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyVerificationOptions::snapshot(options);

    let report = catch_panic_as_py_err("archive verification", || {
        py.detach(|| {
            VerifyRequest::new(&config)
                .with_options(options)
                .verify(&archive_path)
        })
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
/// * `format` - As in `create_archive`
/// * `overwrite` - As in `create_archive`
/// * `durability` - As in `create_archive`
///
/// Progress callback signature: `(path: str, total: int | None, current: int,
/// bytes_written: int) -> None`; `current` counts from 1 and `total` is `None`
/// when the entry count is not known up front (TAR streams)
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
/// # A raising `progress` cancels the creation
///
/// If `progress` raises (`KeyboardInterrupt` included), creation stops at the
/// next entry: the staged archive is discarded, a previous archive at
/// `output_path` stays untouched and no temporary file is left. `progress` is
/// not called again, and its own exception is what propagates, unchanged, with
/// a `progress_callback_error = True` marker attribute.
///
/// If creation fails for its own reason first, the core error takes priority (a
/// raising callback can never mask a security error such as
/// `SymlinkEscapeError`) and the callback's exception is chained onto it via
/// `__cause__`. This error does not carry the `progress_callback_error` marker.
///
/// # Examples
///
/// ```python
/// from exarch import create_archive_with_progress
///
/// def progress(path: str, total: int | None, current: int, bytes: int):
///     print(f"{current}/{total}: {path} ({bytes} bytes)")
///
/// report = create_archive_with_progress(
///     "output.tar.gz", ["src/"], None, progress
/// )
/// ```
#[pyfunction]
#[expect(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    reason = "pyo3 cannot extract `&str` under abi3-py39; the keyword arguments are the Python signature"
)]
#[pyo3(signature = (output_path, sources, config=None, progress=None, format=None, overwrite=true, durability=None))]
fn create_archive_with_progress(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<PyRef<'_, PyCreationConfig>>,
    progress: Option<Py<PyAny>>,
    format: Option<String>,
    overwrite: bool,
    durability: Option<String>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_boundary(py, output_path)?;
    let source_paths = source_boundary_paths(py, sources)?;
    let config = PyCreationConfig::snapshot(config);
    let output = output_file(
        &output_path,
        overwrite,
        format.as_deref(),
        durability.as_deref(),
    )?;

    let report = run_with_optional_progress(
        py,
        "archive creation with progress",
        progress,
        |progress| {
            CreateRequest::new(&config)
                .with_progress(progress)
                .create(&output, &source_paths)
        },
        |exc, report| {
            let _ = exc.setattr("files_added", report.files_added);
            let _ = exc.setattr("bytes_written", report.bytes_written);
        },
    )?;

    Ok(PyCreationReport::from(report))
}

/// Runs `run` with the Python callback `progress`, or with a no-op reporter
/// when `progress` is absent. The GIL is released either way; the callback's
/// adapter takes it back for each call.
///
/// A raising callback is merged with the result by `merge_progress_result`;
/// `attach` adds counters to the callback's exception when the run succeeded
/// (the successful value is discarded).
pub(crate) fn run_with_optional_progress<T: Send>(
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
            let result = catch_panic_as_py_result(context, || Ok(py.detach(|| run(&mut adapter))))?;
            merge_progress_result(py, result, adapter.into_callback_error(), attach)
        }
    }
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
        (Err(error), Some(cb_err)) if error.is_cancelled() => {
            // The core stopped because the callback asked it to (see
            // `PyProgressAdapter::is_cancelled`); the callback's own exception
            // wins and says what the stop left behind.
            if let Some(outcome) = error.into_ffi_message().partial {
                attach_partial(&cb_err, outcome);
            }
            let _ = cb_err.value(py).setattr("progress_callback_error", true);
            Err(cb_err)
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
/// Progress callback signature: `(path: str, total: int | None, current: int,
/// bytes_written: int) -> None`; `current` counts from 1 and `total` is `None`
/// when the entry count is not known up front (TAR streams)
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
/// The GIL is released during extraction whether or not a callback is given;
/// the callback takes it back for each call. The TOCTOU caveat from
/// `extract_archive` still applies.
///
/// ## A raising `progress` cancels the extraction
///
/// If `progress` raises (`KeyboardInterrupt` included), extraction stops at the
/// next entry and `progress` is not called again. What was written stays on
/// disk (or is rolled back under an atomic `staging`), exactly as for any other
/// late failure.
///
/// - The callback's own exception is what propagates, with a
///   `progress_callback_error = True` marker attribute and `writes` (and, while
///   the files remain on disk, `files_extracted`, `bytes_written`,
///   `files_skipped`, `skipped` and `warnings`) describing what was written.
///   Attribute attachment is best-effort (`setattr` can fail, e.g. for an
///   exception class using `__slots__`). The marker exists because those
///   counters are the *same* attribute names a genuine partial extraction
///   carries — check `progress_callback_error` first to tell the two apart.
/// - If the last entry raised and extraction otherwise succeeded, the same
///   exception propagates with the counters of the finished extraction.
/// - If extraction fails for its own reason first, the core error takes
///   priority (a raising callback can never mask a security error such as
///   `SymlinkEscapeError`) and the callback's exception is chained onto it via
///   `__cause__`. This error does not carry the `progress_callback_error`
///   marker.
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive_with_progress
///
/// def progress(path: str, total: int | None, current: int, bytes: int):
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
    config: Option<PyRef<'_, PySecurityConfig>>,
    progress: Option<Py<PyAny>>,
    options: Option<PyRef<'_, PyExtractionOptions>>,
) -> PyResult<PyExtractionReport> {
    let archive_path = path_to_boundary(py, archive_path)?;
    let output_dir = path_to_boundary(py, output_dir)?;
    let config = PySecurityConfig::snapshot(config);
    let options = PyExtractionOptions::snapshot(options);

    let report = run_with_optional_progress(
        py,
        "archive extraction with progress",
        progress,
        |progress| {
            ExtractRequest::new(&config)
                .with_options(options)
                .with_progress(progress)
                .extract(&archive_path, &output_dir)
        },
        |exc, report| {
            let _ = exc.setattr("files_extracted", report.files_extracted);
            let _ = exc.setattr("bytes_written", report.bytes_written);
        },
    )?;

    Ok(PyExtractionReport::from(report))
}

/// Adapter that calls Python callback from Rust.
///
/// The Python callback receives `(path: str, total: int | None, current: int,
/// bytes_written: int)` (`total` is `None` for an unknown count) where
/// `bytes_written` is always 0: the core reports byte counts per chunk, which
/// the binding does not forward.
///
/// If the callback raises, the exception is captured into `callback_error`
/// instead of being discarded (see issue #489) and
/// [`is_cancelled`](exarch_core::ProgressCallback::is_cancelled) turns true, so
/// the core stops at the next entry; once a raise has been captured, further
/// dispatches are skipped. The caller retrieves the captured exception via
/// [`into_callback_error`](Self::into_callback_error) once the core
/// operation returns, and raises it to the Python caller.
struct PyProgressAdapter {
    callback: Py<PyAny>,
    callback_error: Option<PyErr>,
}

impl PyProgressAdapter {
    fn new(callback: Py<PyAny>) -> Self {
        Self {
            callback,
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
    fn on_entry_start(&mut self, path: &std::path::Path, position: exarch_core::EntryPosition) {
        let total = position.total.known();
        let current = position.current.get();
        if self.callback_error.is_some() {
            return;
        }
        Python::attach(|py| {
            if let Err(err) = self
                .callback
                .call1(py, (path.as_os_str(), total, current, 0_u64))
            {
                self.callback_error = Some(err);
            }
        });
    }

    fn on_bytes_written(&mut self, _bytes: u64) {
        // No-op: the callback's `bytes_written` is always 0
    }

    fn on_entry_complete(&mut self, _path: &std::path::Path) {
        // No-op: not exposed to Python (simplification)
    }

    fn on_complete(&mut self) {
        // No-op: Python can detect completion when function returns
    }

    /// A callback that raised (`KeyboardInterrupt` included) cancels the
    /// operation, so a creation does not commit its staged archive. The
    /// recorded exception, not the core's `Interrupted` error, is what the
    /// caller sees (see `merge_progress_result`).
    fn is_cancelled(&mut self) -> bool {
        self.callback_error.is_some()
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
    m.add_function(wrap_pyfunction!(buffer::list_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(buffer::verify_archive_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(buffer::extract_archive_to_memory, m)?)?;
    m.add_function(wrap_pyfunction!(buffer::extract_archive_to_callback, m)?)?;
    m.add_function(wrap_pyfunction!(
        buffer::extract_archive_to_memory_with_progress,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(buffer::create_archive_to_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(
        buffer::list_archive_bytes_with_progress,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        buffer::verify_archive_bytes_with_progress,
        m
    )?)?;
    #[cfg(feature = "panic-injection")]
    m.add_function(wrap_pyfunction!(_trigger_panic_for_testing, m)?)?;

    // Configuration classes
    m.add_class::<PySecurityConfig>()?;
    m.add_class::<PyCreationConfig>()?;
    m.add_class::<PyExtractionOptions>()?;
    m.add_class::<PyVerificationOptions>()?;

    // Report classes
    m.add_class::<PyExtractionReport>()?;
    m.add_class::<PyCreationReport>()?;
    m.add_class::<PyArchiveManifest>()?;
    m.add_class::<PyArchiveEntry>()?;
    m.add_class::<report::PyEntryDisposition>()?;
    m.add_class::<report::PyExtractDisposition>()?;
    m.add_class::<report::PySkipDisposition>()?;
    m.add_class::<report::PyArchiveFile>()?;
    m.add_class::<report::PyArchiveDirectory>()?;
    m.add_class::<report::PyArchiveSymlink>()?;
    m.add_class::<report::PyArchiveHardlink>()?;
    m.add_class::<report::PyLinkTarget>()?;
    m.add_class::<report::PyRecordedLinkTarget>()?;
    m.add_class::<report::PyMissingLinkTarget>()?;
    m.add_class::<report::PyUnreadLinkTarget>()?;
    m.add_class::<report::PyUnreadableLinkTarget>()?;
    m.add_class::<report::PyOversizedLinkTarget>()?;
    m.add_class::<PyVerificationReport>()?;
    m.add_class::<PyVerificationIssue>()?;
    m.add_class::<PyIntegrityGaps>()?;
    m.add_class::<PyUnverifiedEntry>()?;
    m.add_class::<report::PySkips>()?;
    m.add_class::<report::PySkip>()?;
    m.add_class::<warning::PyExtractionWarning>()?;
    m.add_class::<warning::PyAntiItemsSkippedWarning>()?;
    m.add_class::<warning::PyBackupCleanupFailedWarning>()?;
    m.add_class::<warning::PyCreationWarning>()?;
    m.add_class::<warning::PyZipRatioOverDefaultLimitWarning>()?;
    m.add_class::<warning::PyZipRatioCheckFailedWarning>()?;
    m.add_class::<warning::PyDirectoryNotSyncedWarning>()?;
    m.add_class::<buffer::PySinkOptions>()?;
    m.add_class::<buffer::PyMemoryEntry>()?;
    m.add_class::<buffer::PyMemoryFile>()?;
    m.add_class::<buffer::PyMemoryDirectory>()?;
    m.add_class::<buffer::PyMemorySymlink>()?;
    m.add_class::<buffer::PyMemoryHardlink>()?;
    m.add_class::<buffer::PyMemoryExtraction>()?;
    m.add_class::<buffer::PyCreatedArchive>()?;

    // Exception types
    register_exceptions(m)?;

    register_type_aliases(m)?;

    Ok(())
}

/// Exports the typing aliases the stub declares, so `from exarch import
/// AnyMemoryEntry` works at runtime as it does for a type checker.
fn register_type_aliases(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    let typing = py.import("typing")?;
    let union = typing.getattr("Union")?;
    let union_of = |names: &[&str]| -> PyResult<Bound<'_, PyAny>> {
        let members = names
            .iter()
            .map(|name| m.getattr(*name))
            .collect::<PyResult<Vec<_>>>()?;
        union.get_item(pyo3::types::PyTuple::new(py, members)?)
    };
    m.add(
        "AnyMemoryEntry",
        union_of(&[
            "MemoryFile",
            "MemoryDirectory",
            "MemorySymlink",
            "MemoryHardlink",
        ])?,
    )?;
    m.add(
        "AnyArchiveEntry",
        union_of(&[
            "ArchiveFile",
            "ArchiveDirectory",
            "ArchiveSymlink",
            "ArchiveHardlink",
        ])?,
    )?;
    m.add(
        "AnyEntryDisposition",
        union_of(&["ExtractDisposition", "SkipDisposition"])?,
    )?;
    m.add(
        "AnyExtractionWarning",
        union_of(&["AntiItemsSkippedWarning", "BackupCleanupFailedWarning"])?,
    )?;
    m.add(
        "AnyCreationWarning",
        union_of(&[
            "ZipRatioOverDefaultLimitWarning",
            "ZipRatioCheckFailedWarning",
            "DirectoryNotSyncedWarning",
        ])?,
    )?;
    m.add(
        "AnyLinkTarget",
        union_of(&[
            "RecordedLinkTarget",
            "MissingLinkTarget",
            "UnreadLinkTarget",
            "UnreadableLinkTarget",
            "OversizedLinkTarget",
        ])?,
    )?;

    let optional_int = typing
        .getattr("Optional")?
        .get_item(py.get_type::<pyo3::types::PyInt>())?;
    let parameters = pyo3::types::PyList::new(
        py,
        [
            py.get_type::<pyo3::types::PyString>().into_any(),
            optional_int,
            py.get_type::<pyo3::types::PyInt>().into_any(),
            py.get_type::<pyo3::types::PyInt>().into_any(),
        ],
    )?;
    m.add(
        "ProgressCallbackFn",
        typing
            .getattr("Callable")?
            .get_item((parameters, py.None()))?,
    )?;
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
    fn test_path_to_boundary_with_string() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test.tar.gz").into_any();
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
            assert!(
                result.is_ok(),
                "Failed to convert string path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_boundary_empty() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "").into_any();
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
            assert!(
                result.is_ok(),
                "Failed to convert empty path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "");
        });
    }

    #[test]
    fn test_path_to_boundary_with_path_object() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let pathlib = py.import("pathlib").expect("Failed to import pathlib");
            let path_class = pathlib.getattr("Path").expect("Failed to get Path class");
            let path = path_class
                .call1(("/tmp/test.tar.gz",))
                .expect("Failed to create Path object");
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
            assert!(
                result.is_ok(),
                "Failed to convert Path object: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_boundary_rejects_null_bytes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test\0malicious.tar.gz").into_any();
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
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
    fn test_path_to_boundary_rejects_too_long() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
            let path = PyString::new(py, &long_path).into_any();
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
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
    fn test_path_to_boundary_accepts_max_length() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let max_path = "x".repeat(MAX_PATH_LENGTH);
            let path = PyString::new(py, &max_path).into_any();
            let result = path_to_boundary(py, &path.as_borrowed())
                .map(|path| path.as_path().display().to_string());
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
                exarch_core::EntryPosition::at_index(0, exarch_core::EntryTotal::Known(2)),
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
                exarch_core::EntryPosition::at_index(1, exarch_core::EntryTotal::Known(2)),
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

    /// Attaches `exarch_core::CreationReport` counters onto a
    /// callback exception, matching the closure passed to
    /// `merge_progress_result` at the real `create_archive_with_progress`
    /// call site.
    fn attach_creation_attrs(exc: &Bound<'_, PyAny>, report: &exarch_core::CreationReport) {
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
            let report = {
                let mut r = exarch_core::ExtractionReport::new();
                r.files_extracted = 3;
                r.bytes_written = 42;
                r
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
            let report = {
                let mut r = exarch_core::ExtractionReport::new();
                r.files_extracted = 1;
                r
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
            let report = {
                let mut r = exarch_core::CreationReport::new();
                r.files_added = 2;
                r.bytes_written = 17;
                r
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
            let report = {
                let mut r = exarch_core::CreationReport::new();
                r.files_added = 1;
                r
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

    /// A cancellation seen through `PartialExtraction`: the callback's own
    /// exception wins and says what the stop left on disk.
    #[test]
    fn test_merge_cancelled_partial_extraction_keeps_callback_error_with_writes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let report = {
                let mut r = exarch_core::ExtractionReport::new();
                r.files_extracted = 2;
                r.bytes_written = 9;
                r
            };
            let cancelled =
                exarch_core::ArchiveError::PartialExtraction(exarch_core::Partial::new(
                    exarch_core::ArchiveError::Cancelled,
                    report,
                    exarch_core::PartialWrites::Kept,
                ));
            let cb_err = PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("callback boom");

            let err =
                merge_progress_result(py, Err(cancelled), Some(cb_err), attach_extraction_attrs)
                    .expect_err("callback exception must propagate");

            assert!(err.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py));
            let value = err.value(py);
            let marker: bool = value
                .getattr("progress_callback_error")
                .unwrap()
                .extract()
                .unwrap();
            let writes: String = value.getattr("writes").unwrap().extract().unwrap();
            let files: usize = value.getattr("files_extracted").unwrap().extract().unwrap();
            assert!(marker);
            assert_eq!((writes.as_str(), files), ("kept", 2));
        });
    }
}
