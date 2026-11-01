//! Archives held in memory instead of on disk.

use std::num::NonZeroU64;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::MemoryEntry;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PathModel;
use exarch_core::SanitizedMode;
use exarch_core::formats::detect::ArchiveType;
use pyo3::exceptions::PyRuntimeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

use crate::catch_panic_as_py_err;
use crate::config::PyExtractionOptions;
use crate::config::PySecurityConfig;
use crate::config::PyVerificationOptions;
use crate::error::convert_error;
use crate::report::PyArchiveManifest;
use crate::report::PyExtractionReport;
use crate::report::PyVerificationReport;

/// Parses the string form of a closed core enum (`ALL` and `as_str`).
fn parse_variant<T: Copy>(
    what: &str,
    all: &[T],
    as_str: fn(T) -> &'static str,
    value: Option<&str>,
) -> PyResult<Option<T>> {
    value
        .map(|value| {
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
        })
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

/// What a [`PyMemoryEntry`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryEntryKind {
    File,
    Directory,
    Symlink,
}

impl MemoryEntryKind {
    #[cfg(test)]
    const ALL: &'static [Self] = &[Self::File, Self::Directory, Self::Symlink];

    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }
}

/// An entry extracted into memory.
///
/// # Attributes
///
/// * `path` - Entry path, relative, as delivered by extraction
/// * `kind` - `"file"`, `"directory"` or `"symlink"`
/// * `data` - The file's bytes (`None` unless `kind` is `"file"`)
/// * `mode` - Permission bits after setuid and setgid were stripped (`None`
///   unless a file whose archive carries a mode)
/// * `target` - Symlink target as the archive spells it (`None` unless `kind`
///   is `"symlink"`)
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
        let (kind, data, mode, target) = match entry {
            MemoryEntry::File { data, mode } => (
                MemoryEntryKind::File,
                Some(PyBytes::new(py, &data).unbind()),
                mode.map(SanitizedMode::as_u32),
                None,
            ),
            MemoryEntry::Symlink { target } => {
                (MemoryEntryKind::Symlink, None, None, Some(utf8(&target)?))
            }
            MemoryEntry::Directory => (MemoryEntryKind::Directory, None, None, None),
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
                .ok_or_else(|| PyValueError::new_err("max_bytes must be positive"))
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
    data: PyBackedBytes,
    config: Option<&PySecurityConfig>,
    options: Option<&PyExtractionOptions>,
    max_bytes: Option<i128>,
    path_model: Option<String>,
    format: Option<String>,
) -> PyResult<PyMemoryExtraction> {
    let format = parse_format(format.as_deref())?;
    let path_model = parse_path_model(path_model.as_deref())?.unwrap_or_default();
    let max_bytes = parse_max_bytes(max_bytes)?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::ExtractionOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());
    let limit = max_bytes.map_or_else(|| MemoryLimit::from_config(config_ref), MemoryLimit::new);

    let (report, sink) = catch_panic_as_py_err("archive extraction", || {
        py.detach(|| {
            let reader = ArchiveReader::from_bytes(data, format)?;
            let mut sink = MemorySink::new(limit).with_path_model(path_model);
            let report = exarch_core::extract_to_sink(reader, &mut sink, config_ref, options_ref)?;
            Ok((report, sink))
        })
    })?;

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
    data: PyBackedBytes,
    config: Option<&PySecurityConfig>,
    format: Option<String>,
) -> PyResult<PyArchiveManifest> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let options = exarch_core::ListOptions::default();

    let manifest = catch_panic_as_py_err("archive listing", || {
        py.detach(|| {
            let reader = ArchiveReader::from_bytes(data, format)?;
            exarch_core::list_reader(reader, config_ref, &options)
        })
    })?;

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
    data: PyBackedBytes,
    config: Option<&PySecurityConfig>,
    options: Option<&PyVerificationOptions>,
    format: Option<String>,
) -> PyResult<PyVerificationReport> {
    let format = parse_format(format.as_deref())?;
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());
    let default_options = exarch_core::VerificationOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    let report = catch_panic_as_py_err("archive verification", || {
        py.detach(|| {
            let reader = ArchiveReader::from_bytes(data, format)?;
            exarch_core::verify_reader(reader, config_ref, options_ref)
        })
    })?;

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
