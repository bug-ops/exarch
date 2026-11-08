//! Typed warnings of extraction and creation reports.
//!
//! Core reports warnings as enums; flattening them to text would leave a caller
//! only English to match. Each core variant becomes a class that carries only
//! its own fields, under a base class every warning shares.

use exarch_core::BackupIdentity;
use exarch_core::CreationWarning;
use exarch_core::ExtractionWarning;
use pyo3::prelude::*;
use pyo3::types::PyList;

/// A condition of an extraction worth surfacing that is not a skipped entry.
///
/// The concrete class tells which condition it is and carries its fields.
///
/// # Attributes
///
/// * `kind` - `"anti_items_skipped"` or `"backup_cleanup_failed"`
/// * `message` - Human-readable description; host paths are redacted like those
///   of an exception message
#[pyclass(name = "ExtractionWarning", subclass, frozen)]
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
}

/// 7z anti-items, which mark deletions in an update archive, were not applied.
///
/// # Attributes
///
/// * `count` - How many anti-items the archive holds
#[pyclass(name = "AntiItemsSkippedWarning", extends = PyExtractionWarning, frozen)]
pub struct PyAntiItemsSkippedWarning {
    #[pyo3(get)]
    count: u64,
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
#[pyclass(name = "BackupCleanupFailedWarning", extends = PyExtractionWarning, frozen)]
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
#[pyclass(name = "CreationWarning", subclass, frozen)]
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
}

/// Default extraction would refuse entries of the finished ZIP archive as a zip
/// bomb, because their compression ratio is over the default limit.
///
/// # Attributes
///
/// * `entries` - How many entries are over the limit
/// * `limit` - The default extraction ratio limit
/// * `needed_ratio` - The smallest ratio limit that admits every entry
#[pyclass(name = "ZipRatioOverDefaultLimitWarning", extends = PyCreationWarning, frozen)]
pub struct PyZipRatioOverDefaultLimitWarning {
    #[pyo3(get)]
    entries: usize,
    #[pyo3(get)]
    limit: f64,
    #[pyo3(get)]
    needed_ratio: f64,
}

/// The finished ZIP archive could not be read back to check its entries against
/// the default extraction ratio limit.
///
/// # Attributes
///
/// * `reason` - Why the archive could not be read back
#[pyclass(name = "ZipRatioCheckFailedWarning", extends = PyCreationWarning, frozen)]
pub struct PyZipRatioCheckFailedWarning {
    #[pyo3(get)]
    reason: String,
}

/// The archive was published, but the directory that holds it could not be
/// synced, so the directory entry may not survive a crash.
///
/// # Attributes
///
/// * `io_kind` - The stable kind of the failure
#[pyclass(name = "DirectoryNotSyncedWarning", extends = PyCreationWarning, frozen)]
pub struct PyDirectoryNotSyncedWarning {
    io_kind: &'static str,
}

#[pymethods]
impl PyDirectoryNotSyncedWarning {
    #[getter]
    const fn io_kind(&self) -> &'static str {
        self.io_kind
    }
}

fn extraction_warning(py: Python<'_>, warning: &ExtractionWarning) -> PyResult<Py<PyAny>> {
    let warning = warning.redacted();
    let base = PyExtractionWarning {
        kind: warning.kind().as_str(),
        message: warning.to_string(),
    };
    let initializer = PyClassInitializer::from(base);
    match &warning {
        ExtractionWarning::AntiItemsSkipped { count } => Bound::new(
            py,
            initializer.add_subclass(PyAntiItemsSkippedWarning { count: *count }),
        )
        .map(Bound::into_any),
        ExtractionWarning::BackupCleanupFailed {
            path,
            identity,
            io_kind,
            message,
        } => Bound::new(
            py,
            initializer.add_subclass(PyBackupCleanupFailedWarning {
                path: path.to_string_lossy().into_owned(),
                identity: *identity,
                io_kind: io_kind.as_str(),
                reason: message.to_string(),
            }),
        )
        .map(Bound::into_any),
        _ => Bound::new(py, initializer).map(Bound::into_any),
    }
    .map(Bound::unbind)
}

fn creation_warning(py: Python<'_>, warning: &CreationWarning) -> PyResult<Py<PyAny>> {
    let warning = warning.redacted();
    let base = PyCreationWarning {
        kind: warning.kind().as_str(),
        message: warning.to_string(),
    };
    let initializer = PyClassInitializer::from(base);
    match &warning {
        CreationWarning::ZipRatioOverDefaultLimit {
            entries,
            limit,
            needed_ratio,
        } => Bound::new(
            py,
            initializer.add_subclass(PyZipRatioOverDefaultLimitWarning {
                entries: *entries,
                limit: *limit,
                needed_ratio: *needed_ratio,
            }),
        )
        .map(Bound::into_any),
        CreationWarning::ZipRatioCheckFailed { reason } => Bound::new(
            py,
            initializer.add_subclass(PyZipRatioCheckFailedWarning {
                reason: reason.clone(),
            }),
        )
        .map(Bound::into_any),
        CreationWarning::DirectoryNotSynced { io_kind } => Bound::new(
            py,
            initializer.add_subclass(PyDirectoryNotSyncedWarning {
                io_kind: io_kind.as_str(),
            }),
        )
        .map(Bound::into_any),
        _ => Bound::new(py, initializer).map(Bound::into_any),
    }
    .map(Bound::unbind)
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert by panicking"
)]
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
