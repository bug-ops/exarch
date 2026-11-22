//! Typed warnings of extraction and creation reports.
//!
//! Core reports warnings as enums; flattening them to text would leave a caller
//! only English to match. Each core variant becomes a class that carries only
//! its own fields, under a base class every warning shares.

use exarch_core::BackupIdentity;
use exarch_core::ClosedEnum;
use exarch_core::CreationWarning;
use exarch_core::CreationWarningKind;
use exarch_core::ExtractionWarning;
use exarch_core::ExtractionWarningKind;
use exarch_core::IoKind;
use exarch_core::NarrowingReason;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;

/// What `__reduce__` returns: the reviver and the arguments to call it with.
type Reduced<'py, Args> = PyResult<(Bound<'py, PyAny>, Args)>;

/// The arguments that rebuild a [`PyBackupCleanupFailedWarning`]: message,
/// path, identity, I/O kind and reason.
type BackupArgs = (String, String, &'static str, &'static str, String);

/// A condition of an extraction worth surfacing that is not a skipped entry.
///
/// The concrete class tells which condition it is and carries its fields.
///
/// # Attributes
///
/// * `kind` - `"anti_items_skipped"`, `"backup_cleanup_failed"` or
///   `"root_access_narrowed"`
/// * `message` - Human-readable description; host paths are redacted like those
///   of an exception message
#[pyclass(name = "ExtractionWarning", subclass, frozen, module = "exarch")]
pub struct PyExtractionWarning {
    kind: &'static str,
    message: String,
}

#[pymethods]
impl PyExtractionWarning {
    #[getter]
    const fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn message(&self) -> &str {
        &self.message
    }

    fn __str__(&self) -> &str {
        &self.message
    }

    fn __repr__(&self) -> String {
        format!(
            "ExtractionWarning(kind={:?}, message={:?})",
            self.kind, self.message
        )
    }

    fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyAny>, (&'static str, String))> {
        Ok((
            reviver(py, "_revive_extraction_warning")?,
            (self.kind, self.message.clone()),
        ))
    }
}

/// 7z anti-items, which mark deletions in an update archive, were not applied.
///
/// # Attributes
///
/// * `count` - How many anti-items the archive holds
#[pyclass(name = "AntiItemsSkippedWarning", extends = PyExtractionWarning, frozen, module = "exarch")]
pub struct PyAntiItemsSkippedWarning {
    #[pyo3(get)]
    count: u64,
}

#[pymethods]
impl PyAntiItemsSkippedWarning {
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, (String, u64)> {
        let message = slf.as_super().get().message.clone();
        Ok((
            reviver(slf.py(), "_revive_anti_items_skipped_warning")?,
            (message, slf.get().count),
        ))
    }
}

/// The backup of the original destination, kept for an atomic replacement,
/// could not be removed and must be cleaned up manually.
///
/// # Attributes
///
/// * `path` - Where the backup remains, redacted like an exception message
/// * `identity` - `"verified"` or `"unverified"`: whether the backup's identity
///   was confirmed before its removal failed
/// * `io_kind` - The stable kind of the removal failure
/// * `reason` - The failure text, redacted like an I/O error message
#[pyclass(name = "BackupCleanupFailedWarning", extends = PyExtractionWarning, frozen, module = "exarch")]
pub struct PyBackupCleanupFailedWarning {
    #[pyo3(get)]
    path: String,
    identity: BackupIdentity,
    io_kind: &'static str,
    #[pyo3(get)]
    reason: String,
}

#[pymethods]
impl PyBackupCleanupFailedWarning {
    #[getter]
    const fn identity(&self) -> &'static str {
        self.identity.as_str()
    }

    #[getter]
    const fn io_kind(&self) -> &'static str {
        self.io_kind
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, BackupArgs> {
        let message = slf.as_super().get().message.clone();
        let this = slf.get();
        Ok((
            reviver(slf.py(), "_revive_backup_cleanup_failed_warning")?,
            (
                message,
                this.path.clone(),
                this.identity.as_str(),
                this.io_kind,
                this.reason.clone(),
            ),
        ))
    }
}

/// The published root of an atomic extraction gives less access than the
/// destination it replaced or filled; one warning is raised per reason.
///
/// # Attributes
///
/// * `reason` - The stable token of why the access was narrowed, for example
///   `"acl_unreadable"` or `"owner_not_kept"`
#[pyclass(name = "RootAccessNarrowedWarning", extends = PyExtractionWarning, frozen, module = "exarch")]
pub struct PyRootAccessNarrowedWarning {
    reason: NarrowingReason,
}

#[pymethods]
impl PyRootAccessNarrowedWarning {
    #[getter]
    const fn reason(&self) -> &'static str {
        self.reason.as_str()
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, (String, &'static str)> {
        let message = slf.as_super().get().message.clone();
        Ok((
            reviver(slf.py(), "_revive_root_access_narrowed_warning")?,
            (message, slf.get().reason.as_str()),
        ))
    }
}

/// A condition of a creation worth surfacing that is not a skipped entry.
///
/// The concrete class tells which condition it is and carries its fields.
///
/// # Attributes
///
/// * `kind` - `"zip_ratio_over_default_limit"`, `"zip_ratio_check_failed"` or
///   `"directory_not_synced"`
/// * `message` - Human-readable description
#[pyclass(name = "CreationWarning", subclass, frozen, module = "exarch")]
pub struct PyCreationWarning {
    kind: &'static str,
    message: String,
}

#[pymethods]
impl PyCreationWarning {
    #[getter]
    const fn kind(&self) -> &'static str {
        self.kind
    }

    #[getter]
    fn message(&self) -> &str {
        &self.message
    }

    fn __str__(&self) -> &str {
        &self.message
    }

    fn __repr__(&self) -> String {
        format!(
            "CreationWarning(kind={:?}, message={:?})",
            self.kind, self.message
        )
    }

    fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyAny>, (&'static str, String))> {
        Ok((
            reviver(py, "_revive_creation_warning")?,
            (self.kind, self.message.clone()),
        ))
    }
}

/// Default extraction would refuse entries of the finished ZIP archive as a zip
/// bomb, because their compression ratio is over the default limit.
///
/// # Attributes
///
/// * `entries` - How many entries are over the limit
/// * `limit` - The default extraction ratio limit
/// * `needed_ratio` - The smallest ratio limit that admits every entry
#[pyclass(name = "ZipRatioOverDefaultLimitWarning", extends = PyCreationWarning, frozen, module = "exarch")]
pub struct PyZipRatioOverDefaultLimitWarning {
    #[pyo3(get)]
    entries: usize,
    #[pyo3(get)]
    limit: f64,
    #[pyo3(get)]
    needed_ratio: f64,
}

#[pymethods]
impl PyZipRatioOverDefaultLimitWarning {
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, (String, usize, f64, f64)> {
        let message = slf.as_super().get().message.clone();
        let this = slf.get();
        Ok((
            reviver(slf.py(), "_revive_zip_ratio_over_default_limit_warning")?,
            (message, this.entries, this.limit, this.needed_ratio),
        ))
    }
}

/// The finished ZIP archive could not be read back to check its entries against
/// the default extraction ratio limit.
///
/// # Attributes
///
/// * `reason` - Why the archive could not be read back
#[pyclass(name = "ZipRatioCheckFailedWarning", extends = PyCreationWarning, frozen, module = "exarch")]
pub struct PyZipRatioCheckFailedWarning {
    #[pyo3(get)]
    reason: String,
}

#[pymethods]
impl PyZipRatioCheckFailedWarning {
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, (String, String)> {
        let message = slf.as_super().get().message.clone();
        Ok((
            reviver(slf.py(), "_revive_zip_ratio_check_failed_warning")?,
            (message, slf.get().reason.clone()),
        ))
    }
}

/// The archive was published, but the directory that holds it could not be
/// synced, so the directory entry may not survive a crash.
///
/// # Attributes
///
/// * `io_kind` - The stable kind of the failure
#[pyclass(name = "DirectoryNotSyncedWarning", extends = PyCreationWarning, frozen, module = "exarch")]
pub struct PyDirectoryNotSyncedWarning {
    io_kind: &'static str,
}

#[pymethods]
impl PyDirectoryNotSyncedWarning {
    #[getter]
    const fn io_kind(&self) -> &'static str {
        self.io_kind
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> Reduced<'py, (String, &'static str)> {
        let message = slf.as_super().get().message.clone();
        Ok((
            reviver(slf.py(), "_revive_directory_not_synced_warning")?,
            (message, slf.get().io_kind),
        ))
    }
}

fn extraction_warning(py: Python<'_>, warning: &ExtractionWarning) -> PyResult<Py<PyAny>> {
    let warning = warning.redacted();
    let message = warning.to_string();
    match &warning {
        ExtractionWarning::AntiItemsSkipped { count } => anti_items_skipped(py, message, *count),
        ExtractionWarning::BackupCleanupFailed {
            path,
            identity,
            io_kind,
            message: reason,
        } => backup_cleanup_failed(
            py,
            message,
            PyBackupCleanupFailedWarning {
                path: path.to_string_lossy().into_owned(),
                identity: *identity,
                io_kind: io_kind.as_str(),
                reason: reason.to_string(),
            },
        ),
        ExtractionWarning::RootAccessNarrowed { reason } => {
            root_access_narrowed(py, message, *reason)
        }
        _ => extraction_base(py, warning.kind(), message),
    }
}

fn extraction_initializer(
    kind: ExtractionWarningKind,
    message: String,
) -> PyClassInitializer<PyExtractionWarning> {
    PyClassInitializer::from(PyExtractionWarning {
        kind: kind.as_str(),
        message,
    })
}

fn extraction_base(
    py: Python<'_>,
    kind: ExtractionWarningKind,
    message: String,
) -> PyResult<Py<PyAny>> {
    Ok(Bound::new(py, extraction_initializer(kind, message))?
        .into_any()
        .unbind())
}

fn anti_items_skipped(py: Python<'_>, message: String, count: u64) -> PyResult<Py<PyAny>> {
    let initializer = extraction_initializer(ExtractionWarningKind::AntiItemsSkipped, message)
        .add_subclass(PyAntiItemsSkippedWarning { count });
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

fn backup_cleanup_failed(
    py: Python<'_>,
    message: String,
    fields: PyBackupCleanupFailedWarning,
) -> PyResult<Py<PyAny>> {
    let initializer = extraction_initializer(ExtractionWarningKind::BackupCleanupFailed, message)
        .add_subclass(fields);
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

fn root_access_narrowed(
    py: Python<'_>,
    message: String,
    reason: NarrowingReason,
) -> PyResult<Py<PyAny>> {
    let initializer = extraction_initializer(ExtractionWarningKind::RootAccessNarrowed, message)
        .add_subclass(PyRootAccessNarrowedWarning { reason });
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

fn creation_warning(py: Python<'_>, warning: &CreationWarning) -> PyResult<Py<PyAny>> {
    let warning = warning.redacted();
    let message = warning.to_string();
    match &warning {
        CreationWarning::ZipRatioOverDefaultLimit {
            entries,
            limit,
            needed_ratio,
        } => zip_ratio_over_default_limit(
            py,
            message,
            PyZipRatioOverDefaultLimitWarning {
                entries: *entries,
                limit: *limit,
                needed_ratio: *needed_ratio,
            },
        ),
        CreationWarning::ZipRatioCheckFailed { reason } => {
            zip_ratio_check_failed(py, message, reason.clone())
        }
        CreationWarning::DirectoryNotSynced { io_kind } => {
            directory_not_synced(py, message, io_kind.as_str())
        }
        _ => creation_base(py, warning.kind(), message),
    }
}

fn creation_initializer(
    kind: CreationWarningKind,
    message: String,
) -> PyClassInitializer<PyCreationWarning> {
    PyClassInitializer::from(PyCreationWarning {
        kind: kind.as_str(),
        message,
    })
}

fn creation_base(
    py: Python<'_>,
    kind: CreationWarningKind,
    message: String,
) -> PyResult<Py<PyAny>> {
    Ok(Bound::new(py, creation_initializer(kind, message))?
        .into_any()
        .unbind())
}

fn zip_ratio_over_default_limit(
    py: Python<'_>,
    message: String,
    fields: PyZipRatioOverDefaultLimitWarning,
) -> PyResult<Py<PyAny>> {
    let initializer = creation_initializer(CreationWarningKind::ZipRatioOverDefaultLimit, message)
        .add_subclass(fields);
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

fn zip_ratio_check_failed(py: Python<'_>, message: String, reason: String) -> PyResult<Py<PyAny>> {
    let initializer = creation_initializer(CreationWarningKind::ZipRatioCheckFailed, message)
        .add_subclass(PyZipRatioCheckFailedWarning { reason });
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

fn directory_not_synced(
    py: Python<'_>,
    message: String,
    io_kind: &'static str,
) -> PyResult<Py<PyAny>> {
    let initializer = creation_initializer(CreationWarningKind::DirectoryNotSynced, message)
        .add_subclass(PyDirectoryNotSyncedWarning { io_kind });
    Ok(Bound::new(py, initializer)?.into_any().unbind())
}

/// The function `exarch` exports under `name` to rebuild a warning from the
/// arguments its `__reduce__` returns.
fn reviver<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    py.import("exarch")?.getattr(name)
}

/// The member of a closed core enum spelled `name`, or `ValueError`.
fn known<T: ClosedEnum + Copy>(name: &str) -> PyResult<T> {
    T::ALL
        .iter()
        .copied()
        .find(|member| member.as_str() == name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown value {name:?}")))
}

/// The static spelling of the member of a closed core enum spelled `name`.
pub fn known_name<T: ClosedEnum + Copy>(name: &str) -> PyResult<&'static str> {
    known::<T>(name).map(ClosedEnum::as_str)
}

#[pyfunction]
#[pyo3(name = "_revive_extraction_warning")]
fn revive_extraction_warning(py: Python<'_>, kind: &str, message: String) -> PyResult<Py<PyAny>> {
    extraction_base(py, known(kind)?, message)
}

#[pyfunction]
#[pyo3(name = "_revive_anti_items_skipped_warning")]
fn revive_anti_items_skipped(py: Python<'_>, message: String, count: u64) -> PyResult<Py<PyAny>> {
    anti_items_skipped(py, message, count)
}

#[pyfunction]
#[pyo3(name = "_revive_backup_cleanup_failed_warning")]
fn revive_backup_cleanup_failed(
    py: Python<'_>,
    message: String,
    path: String,
    identity: &str,
    io_kind: &str,
    reason: String,
) -> PyResult<Py<PyAny>> {
    let fields = PyBackupCleanupFailedWarning {
        path,
        identity: known(identity)?,
        io_kind: known_name::<IoKind>(io_kind)?,
        reason,
    };
    backup_cleanup_failed(py, message, fields)
}

#[pyfunction]
#[pyo3(name = "_revive_root_access_narrowed_warning")]
fn revive_root_access_narrowed(
    py: Python<'_>,
    message: String,
    reason: &str,
) -> PyResult<Py<PyAny>> {
    root_access_narrowed(py, message, known(reason)?)
}

#[pyfunction]
#[pyo3(name = "_revive_creation_warning")]
fn revive_creation_warning(py: Python<'_>, kind: &str, message: String) -> PyResult<Py<PyAny>> {
    creation_base(py, known(kind)?, message)
}

#[pyfunction]
#[pyo3(name = "_revive_zip_ratio_over_default_limit_warning")]
fn revive_zip_ratio_over_default_limit(
    py: Python<'_>,
    message: String,
    entries: usize,
    limit: f64,
    needed_ratio: f64,
) -> PyResult<Py<PyAny>> {
    let fields = PyZipRatioOverDefaultLimitWarning {
        entries,
        limit,
        needed_ratio,
    };
    zip_ratio_over_default_limit(py, message, fields)
}

#[pyfunction]
#[pyo3(name = "_revive_zip_ratio_check_failed_warning")]
fn revive_zip_ratio_check_failed(
    py: Python<'_>,
    message: String,
    reason: String,
) -> PyResult<Py<PyAny>> {
    zip_ratio_check_failed(py, message, reason)
}

#[pyfunction]
#[pyo3(name = "_revive_directory_not_synced_warning")]
fn revive_directory_not_synced(
    py: Python<'_>,
    message: String,
    io_kind: &str,
) -> PyResult<Py<PyAny>> {
    directory_not_synced(py, message, known_name::<IoKind>(io_kind)?)
}

/// Registers the private functions that rebuild a pickled warning.
pub fn register_revivers(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(revive_extraction_warning, m)?)?;
    m.add_function(wrap_pyfunction!(revive_anti_items_skipped, m)?)?;
    m.add_function(wrap_pyfunction!(revive_backup_cleanup_failed, m)?)?;
    m.add_function(wrap_pyfunction!(revive_root_access_narrowed, m)?)?;
    m.add_function(wrap_pyfunction!(revive_creation_warning, m)?)?;
    m.add_function(wrap_pyfunction!(revive_zip_ratio_over_default_limit, m)?)?;
    m.add_function(wrap_pyfunction!(revive_zip_ratio_check_failed, m)?)?;
    m.add_function(wrap_pyfunction!(revive_directory_not_synced, m)?)?;
    Ok(())
}

/// The warnings of an extraction report as a Python list of typed warnings.
pub fn extraction_warnings<'py>(
    py: Python<'py>,
    warnings: &[ExtractionWarning],
) -> PyResult<Bound<'py, PyList>> {
    PyList::new(
        py,
        warnings
            .iter()
            .map(|warning| extraction_warning(py, warning))
            .collect::<PyResult<Vec<_>>>()?,
    )
}

/// The warnings of a creation report as a Python list of typed warnings.
pub fn creation_warnings<'py>(
    py: Python<'py>,
    warnings: &[CreationWarning],
) -> PyResult<Bound<'py, PyList>> {
    PyList::new(
        py,
        warnings
            .iter()
            .map(|warning| creation_warning(py, warning))
            .collect::<PyResult<Vec<_>>>()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use exarch_core::IoKind;

    fn attr<'py, T: for<'a> FromPyObject<'a, 'py>>(object: &Bound<'py, PyAny>, name: &str) -> T
    where
        for<'a> <T as FromPyObject<'a, 'py>>::Error: std::fmt::Debug,
    {
        object.getattr(name).unwrap().extract().unwrap()
    }

    #[test]
    fn backup_cleanup_failed_exposes_typed_fields_and_a_redacted_path() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let warning = ExtractionWarning::BackupCleanupFailed {
                path: "/srv/private/backup".into(),
                identity: BackupIdentity::Unverified,
                io_kind: IoKind::PermissionDenied,
                message: "permission denied".into(),
            };
            let object = extraction_warning(py, &warning).unwrap().into_bound(py);

            assert!(object.cast::<PyBackupCleanupFailedWarning>().is_ok());
            assert!(object.cast::<PyExtractionWarning>().is_ok());
            assert_eq!(attr::<String>(&object, "kind"), "backup_cleanup_failed");
            assert_eq!(attr::<String>(&object, "identity"), "unverified");
            assert_eq!(attr::<String>(&object, "io_kind"), "PermissionDenied");
            assert_eq!(attr::<String>(&object, "reason"), "permission denied");
            let path = attr::<String>(&object, "path");
            assert_eq!(
                path,
                exarch_core::sanitize_path_for_error(std::path::Path::new("/srv/private/backup"))
            );
            assert!(attr::<String>(&object, "message").contains(&path));
        });
    }

    #[test]
    fn root_access_narrowed_exposes_its_reason_token() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            for reason in NarrowingReason::ALL {
                let warning = ExtractionWarning::RootAccessNarrowed { reason: *reason };
                let object = extraction_warning(py, &warning).unwrap().into_bound(py);

                assert!(object.cast::<PyRootAccessNarrowedWarning>().is_ok());
                assert_eq!(attr::<String>(&object, "kind"), "root_access_narrowed");
                assert_eq!(attr::<String>(&object, "reason"), reason.as_str());
            }
        });
    }

    #[test]
    fn each_creation_warning_becomes_its_own_class() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let warnings = [
                CreationWarning::ZipRatioOverDefaultLimit {
                    entries: 2,
                    limit: 100.0,
                    needed_ratio: 250.0,
                },
                CreationWarning::ZipRatioCheckFailed {
                    reason: "invalid Zip archive".into(),
                },
                CreationWarning::DirectoryNotSynced {
                    io_kind: IoKind::StorageFull,
                },
            ];
            let list = creation_warnings(py, &warnings).unwrap();
            let kinds: Vec<String> = list.iter().map(|warning| attr(&warning, "kind")).collect();
            assert_eq!(
                kinds,
                [
                    "zip_ratio_over_default_limit",
                    "zip_ratio_check_failed",
                    "directory_not_synced"
                ]
            );
            let first = list.get_item(0).unwrap();
            assert_eq!(attr::<usize>(&first, "entries"), 2);
            assert!((attr::<f64>(&first, "needed_ratio") - 250.0).abs() < f64::EPSILON);
            assert!(first.cast::<PyZipRatioOverDefaultLimitWarning>().is_ok());
            assert_eq!(
                attr::<String>(&list.get_item(2).unwrap(), "io_kind"),
                "StorageFull"
            );
        });
    }
}
