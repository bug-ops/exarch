//! Python bindings for report types.

use exarch_core::ArchiveEntry;
use exarch_core::ArchiveManifest;
use exarch_core::ConfigSetting;
use exarch_core::CreationReport as CoreCreationReport;
use exarch_core::Disposition;
use exarch_core::DispositionKind;
use exarch_core::ExtractionReport as CoreExtractionReport;
use exarch_core::IntegrityGaps;
use exarch_core::LinkTarget;
use exarch_core::ManifestEntryKind;
use exarch_core::Skip as CoreSkip;
use exarch_core::SkipKind;
use exarch_core::Skips as CoreSkips;
use exarch_core::VerificationIssue;
use exarch_core::VerificationReport;
use pyo3::prelude::*;
use pyo3::types::PyList;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use crate::buffer::parse_one;
use crate::warning::creation_warnings;
use crate::warning::extraction_warnings;

/// One entry an operation left out.
///
/// # Attributes
///
/// * `kind` - Why it was skipped (`"duplicate"`, `"extension_not_allowed"`,
///   `"not_selected"`, `"stripped_away"`, `"excluded"`, `"hidden"`,
///   `"over_max_file_size"`, `"symlink_unsupported"` or `"unreadable"`)
/// * `path` - The entry's path as the operation names it
/// * `io_kind` - The stable kind of the I/O failure behind an `"unreadable"`
///   skip (`"PermissionDenied"`, ...), else `None`
#[pyclass(name = "Skip", frozen)]
pub struct PySkip {
    kind: SkipKind,
    path: PathBuf,
    io_kind: Option<&'static str>,
}

#[pymethods]
impl PySkip {
    #[getter]
    fn kind(&self) -> &'static str {
        self.kind.as_str()
    }

    #[getter]
    fn path(&self) -> &OsStr {
        self.path.as_os_str()
    }

    #[getter]
    const fn io_kind(&self) -> Option<&'static str> {
        self.io_kind
    }

    fn __repr__(&self) -> String {
        format!(
            "Skip(kind={:?}, path={:?})",
            self.kind.as_str(),
            self.path.display().to_string()
        )
    }
}

impl From<&CoreSkip> for PySkip {
    fn from(skip: &CoreSkip) -> Self {
        Self {
            kind: skip.kind,
            path: skip.path.clone(),
            io_kind: skip.io_kind.map(exarch_core::IoKind::as_str),
        }
    }
}

/// Everything an operation left out: exact counts per kind plus a bounded
/// sample of the individual entries.
///
/// # Attributes
///
/// * `total` - How many entries were skipped, over all kinds
/// * `counts` - The exact count of each kind that occurred
/// * `sample` - The first skipped entries (at most 64)
#[pyclass(name = "Skipped", frozen)]
#[derive(Clone)]
pub struct PySkips {
    inner: CoreSkips,
}

#[pymethods]
impl PySkips {
    #[getter]
    fn total(&self) -> usize {
        self.inner.total()
    }

    /// The exact count of `kind`, which must be one of the kind strings.
    fn count(&self, kind: &str) -> PyResult<usize> {
        parse_one::<SkipKind>(ConfigSetting::SkipKind, kind).map(|kind| self.inner.count(kind))
    }

    #[getter]
    fn counts(&self) -> BTreeMap<&'static str, usize> {
        SkipKind::ALL
            .iter()
            .map(|kind| (kind.as_str(), self.inner.count(*kind)))
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    #[getter]
    fn sample(&self) -> Vec<PySkip> {
        self.inner.sample().iter().map(PySkip::from).collect()
    }

    fn __len__(&self) -> usize {
        self.inner.total()
    }

    fn __repr__(&self) -> String {
        format!("Skipped(total={})", self.inner.total())
    }
}

impl From<CoreSkips> for PySkips {
    fn from(inner: CoreSkips) -> Self {
        Self { inner }
    }
}

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
///
/// # Attributes
///
/// * `files_extracted` - Number of files successfully extracted
/// * `directories_created` - Number of directories created
/// * `symlinks_created` - Number of symlinks created
/// * `bytes_written` - Total bytes written to disk
/// * `duration_ms` - Extraction duration in milliseconds
/// * `files_skipped` - Number of entries skipped
/// * `skipped` - The skipped entries by kind
/// * `warnings` - List of typed warnings
#[pyclass(name = "ExtractionReport")]
#[derive(Clone)]
pub struct PyExtractionReport {
    inner: CoreExtractionReport,
}

#[pymethods]
impl PyExtractionReport {
    /// Number of files successfully extracted.
    #[getter]
    fn files_extracted(&self) -> usize {
        self.inner.files_extracted
    }

    /// Number of directories created.
    #[getter]
    fn directories_created(&self) -> usize {
        self.inner.directories_created
    }

    /// Number of symlinks created.
    #[getter]
    fn symlinks_created(&self) -> usize {
        self.inner.symlinks_created
    }

    /// Total bytes written to disk.
    #[getter]
    fn bytes_written(&self) -> u64 {
        self.inner.bytes_written
    }

    /// Extraction duration in milliseconds.
    #[getter]
    fn duration_ms(&self) -> u128 {
        self.inner.duration.as_millis()
    }

    /// Number of entries skipped, over all kinds.
    #[getter]
    fn files_skipped(&self) -> usize {
        self.inner.files_skipped()
    }

    /// The skipped entries by kind.
    #[getter]
    fn skipped(&self) -> PySkips {
        PySkips::from(self.inner.skipped.clone())
    }

    /// Returns the typed warnings (`AntiItemsSkippedWarning`,
    /// `BackupCleanupFailedWarning`).
    ///
    /// # Performance
    ///
    /// This method builds a new list on each access. If you need to access the
    /// warnings multiple times, cache the result in a local variable.
    #[getter]
    fn warnings<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        extraction_warnings(py, &self.inner.warnings)
    }

    /// Returns total number of items processed.
    fn total_items(&self) -> usize {
        self.inner.total_items()
    }

    /// Returns whether any warnings were generated.
    fn has_warnings(&self) -> bool {
        self.inner.has_warnings()
    }

    /// Returns a human-readable string representation.
    ///
    /// # Performance
    ///
    /// This method allocates a new string on every call using `format!`.
    /// This is acceptable for debugging/logging but avoid calling in hot paths.
    fn __str__(&self) -> String {
        format!(
            "ExtractionReport(files={}, dirs={}, symlinks={}, bytes={}, duration={}ms, skipped={}, warnings={})",
            self.inner.files_extracted,
            self.inner.directories_created,
            self.inner.symlinks_created,
            self.inner.bytes_written,
            self.inner.duration.as_millis(),
            self.inner.files_skipped(),
            self.inner.warnings.len()
        )
    }

    /// Returns a debug string representation.
    ///
    /// # Performance
    ///
    /// This method allocates a new string on every call (delegates to
    /// `__str__`).
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<CoreExtractionReport> for PyExtractionReport {
    fn from(inner: CoreExtractionReport) -> Self {
        Self { inner }
    }
}

/// Report of an archive creation operation.
///
/// # Attributes
///
/// * `files_added` - Number of files added
/// * `directories_added` - Number of directories added
/// * `symlinks_added` - Number of symlinks added
/// * `bytes_written` - Total uncompressed bytes
/// * `bytes_compressed` - Total compressed bytes
/// * `duration_ms` - Creation duration in milliseconds
/// * `files_skipped` - Number of files skipped
/// * `warnings` - List of typed warnings
#[pyclass(name = "CreationReport")]
#[derive(Clone)]
pub struct PyCreationReport {
    inner: CoreCreationReport,
}

#[pymethods]
impl PyCreationReport {
    #[getter]
    fn files_added(&self) -> usize {
        self.inner.files_added
    }

    #[getter]
    fn directories_added(&self) -> usize {
        self.inner.directories_added
    }

    #[getter]
    fn symlinks_added(&self) -> usize {
        self.inner.symlinks_added
    }

    #[getter]
    fn bytes_written(&self) -> u64 {
        self.inner.bytes_written
    }

    #[getter]
    fn bytes_compressed(&self) -> u64 {
        self.inner.bytes_compressed
    }

    #[getter]
    fn duration_ms(&self) -> u128 {
        self.inner.duration.as_millis()
    }

    #[getter]
    fn files_skipped(&self) -> usize {
        self.inner.files_skipped()
    }

    #[getter]
    fn skipped(&self) -> PySkips {
        PySkips::from(self.inner.skipped.clone())
    }

    #[getter]
    fn warnings<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        creation_warnings(py, &self.inner.warnings)
    }

    fn total_items(&self) -> usize {
        self.inner.total_items()
    }

    fn has_warnings(&self) -> bool {
        self.inner.has_warnings()
    }

    fn compression_ratio(&self) -> f64 {
        self.inner.compression_ratio()
    }

    fn compression_percentage(&self) -> f64 {
        self.inner.compression_percentage()
    }

    fn __str__(&self) -> String {
        format!(
            "CreationReport(files={}, dirs={}, symlinks={}, bytes_written={}, bytes_compressed={}, duration={}ms, skipped={}, warnings={})",
            self.inner.files_added,
            self.inner.directories_added,
            self.inner.symlinks_added,
            self.inner.bytes_written,
            self.inner.bytes_compressed,
            self.inner.duration.as_millis(),
            self.inner.files_skipped(),
            self.inner.warnings.len()
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<CoreCreationReport> for PyCreationReport {
    fn from(inner: CoreCreationReport) -> Self {
        Self { inner }
    }
}

/// Single entry in archive manifest.
///
/// The concrete class tells the kind: `ArchiveFile` (the only one with a
/// `size`), `ArchiveDirectory`, `ArchiveSymlink` or `ArchiveHardlink` (both
/// with a `target`).
///
/// # Attributes
///
/// * `path` - Entry path; a name that is not valid UTF-8 is decoded with
///   `os.fsdecode` (lossless on Unix), never replaced
/// * `entry_type` - `"File"`, `"Directory"`, `"Symlink"` or `"Hardlink"`
/// * `compressed_size` - Compressed size when the format reports one
/// * `mode` - Unix permission bits when the archive records them
/// * `modified` - Modification time as seconds since the Unix epoch (negative
///   before it) when the archive records one
#[pyclass(name = "ArchiveEntry", subclass, frozen)]
#[derive(Clone)]
pub struct PyArchiveEntry {
    inner: ArchiveEntry,
}

#[pymethods]
impl PyArchiveEntry {
    #[getter]
    fn path(&self) -> &OsStr {
        self.inner.path.as_os_str()
    }

    #[getter]
    fn entry_type(&self) -> &'static str {
        self.inner.kind.entry_type().as_str()
    }

    #[getter]
    fn compressed_size(&self) -> Option<u64> {
        self.inner.compressed_size()
    }

    #[getter]
    fn mode(&self) -> Option<u32> {
        self.inner.mode.map(exarch_core::RawMode::get)
    }

    #[getter]
    fn modified(&self) -> Option<f64> {
        self.inner.modified.map(|time| {
            time.duration_since(UNIX_EPOCH).map_or_else(
                |before| -before.duration().as_secs_f64(),
                |after| after.as_secs_f64(),
            )
        })
    }

    fn compression_ratio(&self) -> Option<f64> {
        self.inner.compression_ratio()
    }

    fn __repr__(&self) -> String {
        format!(
            "ArchiveEntry(path={:?}, type={})",
            self.inner.path.display().to_string(),
            self.inner.kind.entry_type()
        )
    }
}

/// A regular file of the manifest.
///
/// # Attributes
///
/// * `size` - Uncompressed size in bytes
#[pyclass(name = "ArchiveFile", extends = PyArchiveEntry, frozen)]
pub struct PyArchiveFile {
    size: u64,
}

#[pymethods]
impl PyArchiveFile {
    #[getter]
    const fn size(&self) -> u64 {
        self.size
    }
}

/// A directory of the manifest.
#[pyclass(name = "ArchiveDirectory", extends = PyArchiveEntry, frozen)]
pub struct PyArchiveDirectory;

/// A symbolic link of the manifest.
///
/// # Attributes
///
/// * `target` - What listing learned of the link target
#[pyclass(name = "ArchiveSymlink", extends = PyArchiveEntry, frozen)]
pub struct PyArchiveSymlink {
    target: Py<PyLinkTarget>,
}

#[pymethods]
impl PyArchiveSymlink {
    #[getter]
    fn target(&self, py: Python<'_>) -> Py<PyLinkTarget> {
        self.target.clone_ref(py)
    }
}

/// A hard link of the manifest.
///
/// # Attributes
///
/// * `target` - What listing learned of the link target
#[pyclass(name = "ArchiveHardlink", extends = PyArchiveEntry, frozen)]
pub struct PyArchiveHardlink {
    target: Py<PyLinkTarget>,
}

#[pymethods]
impl PyArchiveHardlink {
    #[getter]
    fn target(&self, py: Python<'_>) -> Py<PyLinkTarget> {
        self.target.clone_ref(py)
    }
}

impl PyArchiveEntry {
    /// The Python object of `entry`: the class of its kind.
    pub fn into_py(py: Python<'_>, entry: ArchiveEntry) -> PyResult<Py<Self>> {
        let kind = entry.kind.clone();
        let base = Self { inner: entry };
        let init = PyClassInitializer::from(base);
        match kind {
            ManifestEntryKind::File { size } => {
                Bound::new(py, init.add_subclass(PyArchiveFile { size: size.0 }))
                    .map(|e| e.into_super().unbind())
            }
            ManifestEntryKind::Directory => Bound::new(py, init.add_subclass(PyArchiveDirectory))
                .map(|e| e.into_super().unbind()),
            ManifestEntryKind::Symlink { target } => Bound::new(
                py,
                init.add_subclass(PyArchiveSymlink {
                    target: PyLinkTarget::into_py(py, target)?,
                }),
            )
            .map(|e| e.into_super().unbind()),
            ManifestEntryKind::Hardlink { target } => Bound::new(
                py,
                init.add_subclass(PyArchiveHardlink {
                    target: PyLinkTarget::into_py(py, target)?,
                }),
            )
            .map(|e| e.into_super().unbind()),
            _ => Bound::new(py, init).map(Bound::unbind),
        }
    }
}

/// The string form of a link target state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Recorded,
    Missing,
    Unread,
    Unreadable,
    Oversized,
}

impl LinkState {
    #[cfg(test)]
    pub const ALL: &'static [Self] = &[
        Self::Recorded,
        Self::Missing,
        Self::Unread,
        Self::Unreadable,
        Self::Oversized,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Missing => "missing",
            Self::Unread => "unread",
            Self::Unreadable => "unreadable",
            Self::Oversized => "oversized",
        }
    }
}

/// What listing learned of a link's target; the class tells the `state`.
///
/// `RecordedLinkTarget` has the `path`, `OversizedLinkTarget` the `bytes` of
/// the target that was too long to keep. A 7z symlink is `UnreadLinkTarget`:
/// listing does not decode 7z entry data.
#[pyclass(name = "LinkTarget", subclass, frozen)]
pub struct PyLinkTarget;

#[pymethods]
impl PyLinkTarget {
    /// The state of a target this binding has no class for; every known class
    /// overrides it.
    #[classattr]
    fn state() -> &'static str {
        "unknown"
    }
}

/// A link target the archive records.
#[pyclass(name = "RecordedLinkTarget", extends = PyLinkTarget, frozen)]
pub struct PyRecordedLinkTarget {
    path: PathBuf,
}

#[pymethods]
impl PyRecordedLinkTarget {
    #[classattr]
    fn state() -> &'static str {
        LinkState::Recorded.as_str()
    }

    #[getter]
    fn path(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

/// A link whose archive entry carries no target.
#[pyclass(name = "MissingLinkTarget", extends = PyLinkTarget, frozen)]
pub struct PyMissingLinkTarget;

#[pymethods]
impl PyMissingLinkTarget {
    #[classattr]
    fn state() -> &'static str {
        LinkState::Missing.as_str()
    }
}

/// A link target listing did not read.
#[pyclass(name = "UnreadLinkTarget", extends = PyLinkTarget, frozen)]
pub struct PyUnreadLinkTarget;

#[pymethods]
impl PyUnreadLinkTarget {
    #[classattr]
    fn state() -> &'static str {
        LinkState::Unread.as_str()
    }
}

/// A link target that could not be read.
#[pyclass(name = "UnreadableLinkTarget", extends = PyLinkTarget, frozen)]
pub struct PyUnreadableLinkTarget;

#[pymethods]
impl PyUnreadableLinkTarget {
    #[classattr]
    fn state() -> &'static str {
        LinkState::Unreadable.as_str()
    }
}

/// A link target too long to keep.
#[pyclass(name = "OversizedLinkTarget", extends = PyLinkTarget, frozen)]
pub struct PyOversizedLinkTarget {
    bytes: usize,
}

#[pymethods]
impl PyOversizedLinkTarget {
    #[classattr]
    fn state() -> &'static str {
        LinkState::Oversized.as_str()
    }

    #[getter]
    const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl PyLinkTarget {
    fn into_py(py: Python<'_>, target: LinkTarget) -> PyResult<Py<Self>> {
        let init = PyClassInitializer::from(Self);
        match target {
            LinkTarget::Recorded(path) => {
                Bound::new(py, init.add_subclass(PyRecordedLinkTarget { path }))
                    .map(|t| t.into_super().unbind())
            }
            LinkTarget::Missing => Bound::new(py, init.add_subclass(PyMissingLinkTarget))
                .map(|t| t.into_super().unbind()),
            LinkTarget::Unread => Bound::new(py, init.add_subclass(PyUnreadLinkTarget))
                .map(|t| t.into_super().unbind()),
            LinkTarget::Unreadable => Bound::new(py, init.add_subclass(PyUnreadableLinkTarget))
                .map(|t| t.into_super().unbind()),
            LinkTarget::Oversized { bytes } => {
                Bound::new(py, init.add_subclass(PyOversizedLinkTarget { bytes }))
                    .map(|t| t.into_super().unbind())
            }
            _ => Bound::new(py, init).map(Bound::unbind),
        }
    }
}

/// Archive manifest with entry metadata.
///
/// # Attributes
///
/// * `total_entries` - Total number of entries
/// * `total_size` - Total uncompressed size
/// * `entries` - List of archive entries
/// * `dispositions` - What extraction would do with each entry, under the
///   `SecurityConfig` the manifest was listed with
#[pyclass(name = "ArchiveManifest")]
#[derive(Clone)]
pub struct PyArchiveManifest {
    inner: ArchiveManifest,
    dispositions: Vec<(PathBuf, Disposition)>,
}

#[pymethods]
impl PyArchiveManifest {
    #[getter]
    fn total_entries(&self) -> usize {
        self.inner.total_entries()
    }

    #[getter]
    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }

    #[getter]
    fn entries(&self, py: Python<'_>) -> PyResult<Vec<Py<PyArchiveEntry>>> {
        self.inner
            .entries()
            .iter()
            .cloned()
            .map(|entry| PyArchiveEntry::into_py(py, entry))
            .collect()
    }

    #[getter]
    fn format(&self) -> &'static str {
        self.inner.format().as_str()
    }

    /// What extraction would do with each entry: where it lands, why it is
    /// left out, or that the validation refuses it.
    ///
    /// Computed when the archive was listed, under that call's
    /// `SecurityConfig` (its selection, limits and policies).
    #[getter]
    fn dispositions(&self, py: Python<'_>) -> PyResult<Vec<Py<PyEntryDisposition>>> {
        self.dispositions
            .iter()
            .map(|(path, disposition)| {
                PyEntryDisposition::into_py(py, path.clone(), disposition.clone())
            })
            .collect()
    }

    fn __str__(&self) -> String {
        format!(
            "ArchiveManifest(entries={}, total_size={} bytes, format={})",
            self.inner.total_entries(),
            self.inner.total_size(),
            self.inner.format()
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl PyArchiveManifest {
    /// Wraps a manifest listed under `config`, recording what extraction under
    /// that config would do with each entry.
    pub fn new(inner: ArchiveManifest, config: &exarch_core::SecurityConfig) -> Self {
        let dispositions = inner
            .dispositions(config)
            .map(|(entry, disposition)| (entry.path.clone(), disposition))
            .collect();
        Self {
            inner,
            dispositions,
        }
    }
}

/// What extraction does with one listed entry.
///
/// The concrete class tells which: `ExtractDisposition` (the entry lands at
/// `landing`), `SkipDisposition` (the entry is validated but left out, for
/// `kind`) or `RefuseDisposition` (the entry is refused or cannot be placed).
///
/// # Attributes
///
/// * `action` - `"extract"`, `"skip"` or `"refuse"`
/// * `path` - The entry's path in the archive
#[pyclass(name = "EntryDisposition", subclass, frozen)]
pub struct PyEntryDisposition {
    path: PathBuf,
    action: &'static str,
}

#[pymethods]
impl PyEntryDisposition {
    #[getter]
    fn path(&self) -> &OsStr {
        self.path.as_os_str()
    }

    #[getter]
    const fn action(&self) -> &'static str {
        self.action
    }
}

/// An entry that extraction writes.
///
/// # Attributes
///
/// * `landing` - Where it lands, relative to the destination, after any strip
///   or flatten
#[pyclass(name = "ExtractDisposition", extends = PyEntryDisposition, frozen)]
pub struct PyExtractDisposition {
    landing: PathBuf,
}

#[pymethods]
impl PyExtractDisposition {
    #[classattr]
    fn action() -> &'static str {
        DispositionKind::Extract.as_str()
    }

    #[getter]
    fn landing(&self) -> &OsStr {
        self.landing.as_os_str()
    }
}

/// An entry that is validated but not extracted.
///
/// # Attributes
///
/// * `kind` - Why: `"not_selected"`, `"stripped_away"`,
///   `"extension_not_allowed"`, ...
#[pyclass(name = "SkipDisposition", extends = PyEntryDisposition, frozen)]
pub struct PySkipDisposition {
    kind: SkipKind,
}

#[pymethods]
impl PySkipDisposition {
    #[classattr]
    fn action() -> &'static str {
        DispositionKind::Skip.as_str()
    }

    #[getter]
    fn kind(&self) -> &'static str {
        self.kind.as_str()
    }
}

/// An entry that is refused by validation or policy, or cannot be placed.
#[pyclass(name = "RefuseDisposition", extends = PyEntryDisposition, frozen)]
pub struct PyRefuseDisposition;

#[pymethods]
impl PyRefuseDisposition {
    #[classattr]
    fn action() -> &'static str {
        DispositionKind::Refuse.as_str()
    }
}

impl PyEntryDisposition {
    fn into_py(py: Python<'_>, path: PathBuf, disposition: Disposition) -> PyResult<Py<Self>> {
        let init = PyClassInitializer::from(Self {
            path,
            action: disposition.kind().as_str(),
        });
        match disposition {
            Disposition::Extract(landing) => Bound::new(
                py,
                init.add_subclass(PyExtractDisposition {
                    landing: landing.into_path_buf(),
                }),
            )
            .map(|d| d.into_super().unbind()),
            Disposition::Skip(kind) => {
                Bound::new(py, init.add_subclass(PySkipDisposition { kind }))
                    .map(|d| d.into_super().unbind())
            }
            Disposition::Refuse => Bound::new(py, init.add_subclass(PyRefuseDisposition))
                .map(|d| d.into_super().unbind()),
            _ => Bound::new(py, init).map(Bound::unbind),
        }
    }
}

/// Verification issue.
///
/// # Attributes
///
/// * `severity` - Issue severity level
/// * `message` - Human-readable description
/// * `path` - Entry path that triggered issue (if applicable)
#[pyclass(name = "VerificationIssue")]
#[derive(Clone)]
pub struct PyVerificationIssue {
    inner: VerificationIssue,
}

#[pymethods]
impl PyVerificationIssue {
    #[getter]
    fn severity(&self) -> &'static str {
        self.inner.severity().as_str()
    }

    #[getter]
    fn message(&self) -> String {
        self.inner.message()
    }

    #[getter]
    fn path(&self) -> Option<&OsStr> {
        self.inner.entry_path().map(Path::as_os_str)
    }

    #[getter]
    fn category(&self) -> &'static str {
        self.inner.category().as_str()
    }

    /// The error code of a refusal, as an exception of the same refusal would
    /// carry it; `None` for a heuristic finding.
    #[getter]
    fn code(&self) -> Option<&'static str> {
        self.inner.ffi_kind().map(|kind| kind.code().as_str())
    }

    #[getter]
    fn sub_code(&self) -> Option<&'static str> {
        self.inner.sub_code().map(exarch_core::SubCode::as_str)
    }

    #[getter]
    fn relaxable_by(&self) -> Option<&'static str> {
        self.inner
            .ffi_kind()
            .and_then(exarch_core::FfiKind::relaxable_by)
            .map(exarch_core::PolicySetting::as_str)
    }

    #[getter]
    fn setting(&self) -> Option<&'static str> {
        self.inner
            .ffi_kind()
            .and_then(exarch_core::FfiKind::setting)
            .map(exarch_core::ConfigSetting::as_str)
    }

    /// The stable kind of the I/O failure of an `IO_ERROR` refusal, else
    /// `None`.
    #[getter]
    fn io_kind(&self) -> Option<&'static str> {
        self.inner
            .ffi_kind()
            .and_then(exarch_core::FfiKind::io_kind)
            .map(|kind| exarch_core::IoKind::from(kind).as_str())
    }

    /// The permission bits the finding is about (an invalid-permissions
    /// refusal or an executable file), else `None`.
    #[getter]
    fn mode(&self) -> Option<u32> {
        self.inner.mode().map(exarch_core::RawMode::get)
    }

    fn __str__(&self) -> String {
        format!("[{}] {}", self.inner.severity(), self.inner.message())
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<VerificationIssue> for PyVerificationIssue {
    fn from(inner: VerificationIssue) -> Self {
        Self { inner }
    }
}

/// One entry the integrity check could not verify.
///
/// # Attributes
///
/// * `path` - Entry path inside the archive
/// * `reason` - Stable reason string, e.g. `"solid_policy"`
#[pyclass(name = "UnverifiedEntry")]
#[derive(Clone)]
pub struct PyUnverifiedEntry {
    path: PathBuf,
    #[pyo3(get)]
    reason: &'static str,
}

#[pymethods]
impl PyUnverifiedEntry {
    #[getter]
    fn path(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

/// What a requested integrity check left unverified.
///
/// # Attributes
///
/// * `counts` - Unverified items per reason
/// * `entries` - Unverified entries listed by path (capped)
/// * `omitted` - Entries with a path that did not fit the list
/// * `total` - Total number of unverified items
#[pyclass(name = "IntegrityGaps")]
#[derive(Clone)]
pub struct PyIntegrityGaps {
    inner: IntegrityGaps,
}

#[pymethods]
impl PyIntegrityGaps {
    #[getter]
    fn counts(&self) -> BTreeMap<&'static str, u64> {
        self.inner
            .counts()
            .map(|(reason, count)| (reason.as_str(), count))
            .collect()
    }

    #[getter]
    fn entries(&self) -> Vec<PyUnverifiedEntry> {
        self.inner
            .entries()
            .iter()
            .map(|e| PyUnverifiedEntry {
                path: e.path().to_path_buf(),
                reason: e.reason().as_str(),
            })
            .collect()
    }

    #[getter]
    fn omitted(&self) -> u64 {
        self.inner.omitted()
    }

    #[getter]
    fn total(&self) -> u64 {
        self.inner.total()
    }

    fn __repr__(&self) -> String {
        format!(
            "IntegrityGaps(total={}, listed={}, omitted={})",
            self.inner.total(),
            self.inner.entries().len(),
            self.inner.omitted()
        )
    }
}

/// Verification report.
///
/// # Attributes
///
/// * `status` - Overall verification status
/// * `issues` - List of issues found
/// * `total_entries` - Total entries scanned
/// * `total_size` - Total uncompressed size
#[pyclass(name = "VerificationReport")]
#[derive(Clone)]
pub struct PyVerificationReport {
    inner: VerificationReport,
}

#[pymethods]
impl PyVerificationReport {
    #[getter]
    fn status(&self) -> &'static str {
        self.inner.status().as_str()
    }

    #[getter]
    fn issues(&self) -> Vec<PyVerificationIssue> {
        self.inner
            .issues()
            .iter()
            .cloned()
            .map(PyVerificationIssue::from)
            .collect()
    }

    #[getter]
    fn total_entries(&self) -> usize {
        self.inner.total_entries()
    }

    #[getter]
    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }

    #[getter]
    fn suspicious_entries(&self) -> usize {
        self.inner.suspicious_entries()
    }

    #[getter]
    fn format(&self) -> &'static str {
        self.inner.format().as_str()
    }

    #[getter]
    fn integrity_status(&self) -> &'static str {
        self.inner.integrity_status().as_str()
    }

    #[getter]
    fn integrity_gaps(&self) -> Option<PyIntegrityGaps> {
        self.inner
            .integrity_gaps()
            .cloned()
            .map(|inner| PyIntegrityGaps { inner })
    }

    #[getter]
    fn security_status(&self) -> &'static str {
        self.inner.security_status().as_str()
    }

    fn is_safe(&self) -> bool {
        self.inner.is_safe()
    }

    fn has_critical_issues(&self) -> bool {
        self.inner.has_critical_issues()
    }

    fn __str__(&self) -> String {
        format!(
            "VerificationReport(status={}, issues={}, entries={})",
            self.inner.status(),
            self.inner.issues().len(),
            self.inner.total_entries()
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<VerificationReport> for PyVerificationReport {
    fn from(inner: VerificationReport) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    fn skipped(count: usize) -> exarch_core::Skips {
        let mut skips = exarch_core::Skips::default();
        for i in 0..count {
            let skip = exarch_core::Skip::new(exarch_core::SkipKind::Duplicate, format!("f{i}"));
            assert!(skips.record(skip).is_ok());
        }
        skips
    }
    use exarch_core::Compressed;
    use exarch_core::ManifestEntryKind;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_properties() {
        let mut core_report = CoreExtractionReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.skipped = skipped(1);
        core_report.add_warning(exarch_core::ExtractionWarning::AntiItemsSkipped { count: 1 });

        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(
            py_report.files_extracted(),
            10,
            "files_extracted should be 10"
        );
        assert_eq!(
            py_report.directories_created(),
            5,
            "directories_created should be 5"
        );
        assert_eq!(
            py_report.symlinks_created(),
            2,
            "symlinks_created should be 2"
        );
        assert_eq!(
            py_report.bytes_written(),
            1024,
            "bytes_written should be 1024"
        );
        assert_eq!(py_report.duration_ms(), 500, "duration_ms should be 500");
        assert_eq!(py_report.files_skipped(), 1, "files_skipped should be 1");
        assert_eq!(py_report.total_items(), 17, "total_items should be 17");
        assert!(py_report.has_warnings(), "should have warnings");
        assert_eq!(
            warning_count(&py_report),
            1,
            "warnings list should have 1 item"
        );
    }

    #[test]
    fn test_extraction_report_zero_values() {
        let core_report = CoreExtractionReport::new();
        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(
            py_report.files_extracted(),
            0,
            "files_extracted should default to 0"
        );
        assert_eq!(
            py_report.directories_created(),
            0,
            "directories_created should default to 0"
        );
        assert_eq!(
            py_report.symlinks_created(),
            0,
            "symlinks_created should default to 0"
        );
        assert_eq!(
            py_report.bytes_written(),
            0,
            "bytes_written should default to 0"
        );
        assert_eq!(
            py_report.files_skipped(),
            0,
            "files_skipped should default to 0"
        );
        assert_eq!(
            py_report.total_items(),
            0,
            "total_items should be 0 for empty report"
        );
        assert!(
            !py_report.has_warnings(),
            "should not have warnings by default"
        );
        assert_eq!(
            warning_count(&py_report),
            0,
            "warnings list should be empty"
        );
    }

    #[test]
    fn test_extraction_report_large_values() {
        let mut core_report = CoreExtractionReport::new();
        core_report.files_extracted = 100_000;
        core_report.directories_created = 50_000;
        core_report.bytes_written = 10_000_000_000; // 10 GB
        core_report.duration = Duration::from_hours(1);

        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(
            py_report.files_extracted(),
            100_000,
            "Should handle large file counts"
        );
        assert_eq!(
            py_report.bytes_written(),
            10_000_000_000,
            "Should handle large byte counts"
        );
        assert_eq!(
            py_report.duration_ms(),
            3_600_000,
            "Should convert seconds to milliseconds correctly"
        );
    }

    #[test]
    fn test_extraction_report_str() {
        let core_report = CoreExtractionReport::new();
        let py_report = PyExtractionReport::from(core_report);
        let s = py_report.__str__();
        assert!(
            s.contains("ExtractionReport"),
            "__str__ should contain class name"
        );
        assert!(s.contains("files="), "__str__ should contain files field");
        assert!(s.contains("dirs="), "__str__ should contain dirs field");
        assert!(s.contains("bytes="), "__str__ should contain bytes field");
    }

    #[test]
    fn test_extraction_report_repr() {
        let core_report = CoreExtractionReport::new();
        let py_report = PyExtractionReport::from(core_report);
        let repr_str = py_report.__repr__();
        let str_str = py_report.__str__();
        assert_eq!(
            repr_str, str_str,
            "__repr__ should be equivalent to __str__"
        );
    }

    fn warning_count(report: &PyExtractionReport) -> usize {
        pyo3::Python::initialize();
        Python::attach(|py| report.warnings(py).expect("warnings build").len())
    }

    #[test]
    fn test_warnings_are_typed_and_rebuilt_on_each_access() {
        pyo3::Python::initialize();
        let mut core_report = CoreExtractionReport::new();
        core_report.add_warning(exarch_core::ExtractionWarning::AntiItemsSkipped { count: 1 });
        core_report.add_warning(exarch_core::ExtractionWarning::AntiItemsSkipped { count: 2 });
        let py_report = PyExtractionReport::from(core_report);

        Python::attach(|py| {
            for _ in 0..2 {
                let warnings = py_report.warnings(py).expect("warnings build");
                assert_eq!(warnings.len(), 2);
                let second = warnings.get_item(1).expect("second warning");
                assert!(
                    second
                        .cast::<crate::warning::PyAntiItemsSkippedWarning>()
                        .is_ok()
                );
                let count: u64 = second
                    .getattr("count")
                    .expect("count")
                    .extract()
                    .expect("u64");
                let kind: String = second
                    .getattr("kind")
                    .expect("kind")
                    .extract()
                    .expect("str");
                assert_eq!((count, kind.as_str()), (2, "anti_items_skipped"));
            }
        });
    }

    #[test]
    fn test_creation_report_properties() {
        use exarch_core::CreationReport;

        let mut core_report = CreationReport::new();
        core_report.files_added = 20;
        core_report.directories_added = 10;
        core_report.symlinks_added = 3;
        core_report.bytes_written = 2048;
        core_report.bytes_compressed = 1024;
        core_report.duration = Duration::from_millis(750);
        core_report.skipped = skipped(2);
        core_report.add_warning(exarch_core::CreationWarning::ZipRatioCheckFailed {
            reason: "Skipped file".to_string(),
        });

        let py_report = PyCreationReport::from(core_report);

        assert_eq!(py_report.files_added(), 20, "files_added should be 20");
        assert_eq!(
            py_report.directories_added(),
            10,
            "directories_added should be 10"
        );
        assert_eq!(py_report.symlinks_added(), 3, "symlinks_added should be 3");
        assert_eq!(
            py_report.bytes_written(),
            2048,
            "bytes_written should be 2048"
        );
        assert_eq!(
            py_report.bytes_compressed(),
            1024,
            "bytes_compressed should be 1024"
        );
        assert_eq!(py_report.duration_ms(), 750, "duration_ms should be 750");
        assert_eq!(py_report.files_skipped(), 2, "files_skipped should be 2");
        assert_eq!(py_report.total_items(), 33, "total_items should be 33");
        assert!(py_report.has_warnings(), "should have warnings");
        assert!(
            (py_report.compression_ratio() - 2.0).abs() < 0.001,
            "compression ratio should be approximately 2.0"
        );
        assert!(
            (py_report.compression_percentage() - 50.0).abs() < 0.001,
            "compression percentage should be approximately 50.0"
        );
    }

    #[test]
    fn test_creation_report_str() {
        use exarch_core::CreationReport;

        let core_report = CreationReport::new();
        let py_report = PyCreationReport::from(core_report);
        let s = py_report.__str__();
        assert!(
            s.contains("CreationReport"),
            "__str__ should contain class name"
        );
        assert!(s.contains("files="), "__str__ should contain files field");
        assert!(
            s.contains("bytes_written="),
            "__str__ should contain bytes_written field"
        );
    }

    #[test]
    fn test_archive_entry_properties() {
        let mut entry = ArchiveEntry::new(
            PathBuf::from("test/file.txt"),
            ManifestEntryKind::File {
                size: exarch_core::Uncompressed(512),
            },
        );
        entry.compression = exarch_core::EntryCompression::Entry(Compressed(256));
        entry.mode = Some(exarch_core::RawMode::new(0o644));

        let py_entry = PyArchiveEntry { inner: entry };

        assert_eq!(py_entry.path(), OsStr::new("test/file.txt"));
        assert_eq!(py_entry.entry_type(), "File");
        assert_eq!(py_entry.compressed_size(), Some(256));
        assert_eq!(py_entry.mode(), Some(0o644));
        assert_eq!(py_entry.compression_ratio(), Some(2.0));
    }

    #[test]
    fn test_every_manifest_kind_gets_its_own_class() {
        use exarch_core::LinkTarget;

        pyo3::Python::initialize();
        let kinds = [
            ManifestEntryKind::File {
                size: exarch_core::Uncompressed(1),
            },
            ManifestEntryKind::Directory,
            ManifestEntryKind::Symlink {
                target: LinkTarget::Recorded(PathBuf::from("t")),
            },
            ManifestEntryKind::Hardlink {
                target: LinkTarget::Missing,
            },
        ];
        Python::attach(|py| {
            for kind in kinds {
                let expected = kind.entry_type();
                let entry = ArchiveEntry::new(PathBuf::from("e"), kind);
                let obj = PyArchiveEntry::into_py(py, entry).unwrap();
                let name: String = obj
                    .bind(py)
                    .get_type()
                    .getattr("__name__")
                    .unwrap()
                    .extract()
                    .unwrap();
                assert_eq!(name, format!("Archive{}", expected.as_str()));
                let entry_type: String = obj
                    .bind(py)
                    .getattr("entry_type")
                    .unwrap()
                    .extract()
                    .unwrap();
                assert_eq!(entry_type, expected.as_str());
            }
        });
    }

    #[test]
    fn test_a_refused_disposition_gets_its_own_class() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let obj = PyEntryDisposition::into_py(py, PathBuf::from("bad/x"), Disposition::Refuse)
                .unwrap();
            let obj = obj.bind(py);
            let name: String = obj
                .get_type()
                .getattr("__name__")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(name, "RefuseDisposition");
            let action: String = obj.getattr("action").unwrap().extract().unwrap();
            assert_eq!(action, "refuse");
        });
    }

    #[test]
    fn test_every_link_state_gets_its_own_class() {
        use exarch_core::LinkTarget;

        pyo3::Python::initialize();
        let targets = [
            LinkTarget::Recorded(PathBuf::from("t")),
            LinkTarget::Missing,
            LinkTarget::Unread,
            LinkTarget::Unreadable,
            LinkTarget::Oversized { bytes: 9 },
        ];
        assert_eq!(targets.len(), LinkState::ALL.len());
        Python::attach(|py| {
            for (target, state) in targets.into_iter().zip(LinkState::ALL) {
                let obj = PyLinkTarget::into_py(py, target).unwrap();
                let raised: String = obj.bind(py).getattr("state").unwrap().extract().unwrap();
                assert_eq!(raised, state.as_str());
            }
        });
    }

    #[test]
    fn test_non_utf8_entry_path_is_not_merged_with_its_lossy_twin() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        pyo3::Python::initialize();
        let raw = PathBuf::from(OsString::from_vec(vec![b'a', 0xff]));
        let lossy = PathBuf::from("a\u{fffd}");
        let kind = ManifestEntryKind::Directory;
        Python::attach(|py| {
            let name = |path: &PathBuf| {
                PyArchiveEntry::into_py(py, ArchiveEntry::new(path.clone(), kind.clone()))
                    .unwrap()
                    .into_bound(py)
                    .getattr("path")
                    .unwrap()
            };
            assert!(!name(&raw).eq(name(&lossy)).unwrap());
        });
    }

    #[test]
    fn test_archive_manifest_properties() {
        use exarch_core::ArchiveType;

        let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
        for (name, size) in [("file1.txt", 100), ("file2.txt", 200)] {
            let entry = ArchiveEntry::new(
                PathBuf::from(name),
                ManifestEntryKind::File {
                    size: exarch_core::Uncompressed(size),
                },
            );
            manifest.add_entry(entry).unwrap();
        }

        let py_manifest = PyArchiveManifest::new(manifest, &exarch_core::SecurityConfig::default());

        assert_eq!(py_manifest.total_entries(), 2, "total_entries should be 2");
        assert_eq!(py_manifest.total_size(), 300, "total_size should be 300");
        pyo3::Python::initialize();
        Python::attach(|py| {
            assert_eq!(
                py_manifest.entries(py).unwrap().len(),
                2,
                "entries should have 2 items"
            );
        });
        // Format display varies, just check it's not empty
        assert!(
            !py_manifest.format().is_empty(),
            "format should not be empty"
        );
    }

    #[test]
    fn test_verification_issue_security_policy_category() {
        let error = exarch_core::ArchiveError::from(exarch_core::Violation::EncryptedArchive);
        let issue = VerificationIssue::from_error(&error, None);

        assert_eq!(
            PyVerificationIssue::from(issue).category(),
            "Security Policy"
        );
    }

    #[test]
    fn test_verification_issue_properties() {
        use exarch_core::ArchiveError;
        use std::path::PathBuf;

        let error = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let issue = VerificationIssue::from_error(&error, Some(PathBuf::from("../etc/passwd")));

        let py_issue = PyVerificationIssue::from(issue);

        assert_eq!(
            py_issue.severity(),
            "CRITICAL",
            "severity() forwards IssueSeverity's Display impl, which renders upper-case \
             (matches exarch-cli and exarch-node's own convention)"
        );
        assert_eq!(
            py_issue.message(),
            "Path traversal detected: ../etc/passwd",
            "message should match"
        );
        assert_eq!(
            py_issue.path(),
            Some(OsStr::new("../etc/passwd")),
            "path should match"
        );
        assert_eq!(
            py_issue.category(),
            "Path Traversal",
            "category() forwards IssueCategory's Display impl (matches exarch-cli's JSON output \
             and exarch-node's own convention)"
        );
        assert_eq!(py_issue.code(), Some("PATH_TRAVERSAL"));
        assert_eq!(py_issue.sub_code(), None);
        assert_eq!(py_issue.mode(), None);
    }

    /// One alias per line: drops trailing comments, joins the lines of a
    /// multi-line `Literal[..]` and ignores the formatter's trailing comma and
    /// spacing, so the check holds for `ruff format` output.
    fn flatten_literals(text: &str) -> String {
        let mut out = String::new();
        let mut open = false;
        for raw in text.lines() {
            let line = raw.split("  # ").next().unwrap_or(raw).trim();
            if line.is_empty() {
                continue;
            }
            if !open {
                out.push('\n');
            }
            out.push_str(line);
            open =
                line.contains("Literal[") && !line.ends_with(']') || (open && !line.ends_with(']'));
        }
        out.replace(", ", ",").replace(",]", "]")
    }

    fn literal_line<T: Copy>(alias: &str, all: &[T], as_str: fn(T) -> &'static str) -> String {
        let values: Vec<String> = all.iter().map(|v| format!("\"{}\"", as_str(*v))).collect();
        format!("{alias} = Literal[{}]", values.join(", "))
    }

    #[test]
    fn test_pyi_literal_aliases_match_core_enums() {
        use exarch_core::ArchiveType;
        use exarch_core::CheckStatus;
        use exarch_core::ConfigSetting;
        use exarch_core::CreatableFormat;
        use exarch_core::ErrorCode;
        use exarch_core::IntegrityStatus;
        use exarch_core::InvalidArchiveSubCode;
        use exarch_core::IssueCategory;
        use exarch_core::IssueSeverity;
        use exarch_core::ManifestEntryType;
        use exarch_core::MemoryEntryKind;
        use exarch_core::PartialWrites;
        use exarch_core::PathModel;
        use exarch_core::PolicySetting;
        use exarch_core::SecurityViolationSubCode;
        use exarch_core::SkipKind;
        use exarch_core::SubCode;
        use exarch_core::UnverifiedReason;
        use exarch_core::VerificationStatus;
        use exarch_core::ZipConsistencyPolicy;

        let pyi = include_str!("../exarch.pyi");
        let expected = [
            literal_line("_ArchiveType", ArchiveType::ALL, ArchiveType::as_str),
            literal_line(
                "_ManifestEntryType",
                ManifestEntryType::ALL,
                ManifestEntryType::as_str,
            ),
            literal_line(
                "_VerificationStatus",
                VerificationStatus::ALL,
                VerificationStatus::as_str,
            ),
            literal_line("_CheckStatus", CheckStatus::ALL, CheckStatus::as_str),
            literal_line("_IssueSeverity", IssueSeverity::ALL, IssueSeverity::as_str),
            literal_line("_IssueCategory", IssueCategory::ALL, IssueCategory::as_str),
            literal_line(
                "_IntegrityStatus",
                IntegrityStatus::ALL,
                IntegrityStatus::as_str,
            ),
            literal_line(
                "_UnverifiedReason",
                UnverifiedReason::ALL,
                UnverifiedReason::as_str,
            ),
            literal_line(
                "_ZipConsistency",
                ZipConsistencyPolicy::ALL,
                ZipConsistencyPolicy::as_str,
            ),
            literal_line("_PartialWrites", PartialWrites::ALL, PartialWrites::as_str),
            literal_line("_PolicySetting", PolicySetting::ALL, PolicySetting::as_str),
            literal_line(
                "_SecurityViolationSubCode",
                SecurityViolationSubCode::ALL,
                SecurityViolationSubCode::as_str,
            ),
            literal_line(
                "_InvalidArchiveSubCode",
                InvalidArchiveSubCode::ALL,
                InvalidArchiveSubCode::as_str,
            ),
            literal_line("_PathModel", PathModel::ALL, PathModel::as_str),
            literal_line(
                "_CreatableFormat",
                CreatableFormat::ALL,
                CreatableFormat::as_str,
            ),
            literal_line("_SkipKind", SkipKind::ALL, SkipKind::as_str),
            literal_line("_LinkState", LinkState::ALL, LinkState::as_str),
            literal_line("_ErrorCode", ErrorCode::ALL, ErrorCode::as_str),
            literal_line("_QuotaSubCode", SubCode::QUOTA_ALL, SubCode::as_str),
            literal_line("_ZipBombSubCode", SubCode::ZIP_BOMB_ALL, SubCode::as_str),
            literal_line("_ConfigSetting", ConfigSetting::ALL, ConfigSetting::as_str),
            literal_line(
                "_MemoryEntryKind",
                MemoryEntryKind::ALL,
                MemoryEntryKind::as_str,
            ),
            literal_line(
                "_DecodeReuse",
                exarch_core::DecodeReuseKind::ALL,
                exarch_core::DecodeReuseKind::as_str,
            ),
        ];
        let flat = flatten_literals(pyi);
        for line in expected {
            assert!(
                flat.lines().any(|l| l == flatten_literals(&line).trim()),
                "exarch.pyi is out of sync with exarch-core, expected alias:\n{line}"
            );
        }
    }

    #[test]
    fn test_pyi_literal_aliases_match_core_option_and_warning_enums() {
        let pyi = include_str!("../exarch.pyi");
        let expected = [
            literal_line(
                "_ExistingFiles",
                exarch_core::ExistingFiles::ALL,
                exarch_core::ExistingFiles::as_str,
            ),
            literal_line(
                "_ProtectedPath",
                exarch_core::ProtectedPath::ALL,
                exarch_core::ProtectedPath::as_str,
            ),
            literal_line(
                "_Staging",
                exarch_core::Staging::ALL,
                exarch_core::Staging::as_str,
            ),
            literal_line(
                "_Restore",
                exarch_core::RestoreKind::ALL,
                exarch_core::RestoreKind::as_str,
            ),
            literal_line(
                "_DispositionKind",
                exarch_core::DispositionKind::ALL,
                exarch_core::DispositionKind::as_str,
            ),
            literal_line(
                "_IoKind",
                exarch_core::IoKind::ALL,
                exarch_core::IoKind::as_str,
            ),
            literal_line(
                "_BackupIdentity",
                exarch_core::BackupIdentity::ALL,
                exarch_core::BackupIdentity::as_str,
            ),
            literal_line(
                "_ExtractionWarningKind",
                exarch_core::ExtractionWarningKind::ALL,
                exarch_core::ExtractionWarningKind::as_str,
            ),
            literal_line(
                "_CreationWarningKind",
                exarch_core::CreationWarningKind::ALL,
                exarch_core::CreationWarningKind::as_str,
            ),
        ];
        let flat = flatten_literals(pyi);
        for line in expected {
            assert!(
                flat.lines().any(|l| l == flatten_literals(&line).trim()),
                "exarch.pyi is out of sync with exarch-core, expected alias:\n{line}"
            );
        }
    }

    #[test]
    fn test_pyi_has_one_class_per_manifest_entry_type_and_link_state() {
        use exarch_core::ManifestEntryType;

        let pyi = include_str!("../exarch.pyi");
        for kind in ManifestEntryType::ALL {
            let narrowed = format!("def entry_type(self) -> Literal[\"{}\"]", kind.as_str());
            assert_eq!(pyi.matches(&narrowed).count(), 1, "{kind:?}");
        }
        for state in LinkState::ALL {
            let narrowed = format!("def state(self) -> Literal[\"{}\"]", state.as_str());
            assert_eq!(pyi.matches(&narrowed).count(), 1, "{state:?}");
        }
    }

    #[test]
    fn test_pyi_has_one_memory_entry_class_per_kind() {
        use exarch_core::MemoryEntryKind;

        let pyi = include_str!("../exarch.pyi");
        for kind in MemoryEntryKind::ALL {
            let narrowed = format!("def kind(self) -> Literal[\"{}\"]", kind.as_str());
            assert_eq!(
                pyi.matches(&narrowed).count(),
                1,
                "exarch.pyi needs exactly one MemoryEntry subclass narrowing kind to {kind:?}"
            );
        }
    }

    // NOTE: VerificationReport tests removed as they depend on types that may
    // not be public in core. The type wrappers are tested via Python
    // integration tests.
}
