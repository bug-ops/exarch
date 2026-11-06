//! Python exception types for archive extraction errors.

use exarch_core::ArchiveError as CoreError;
use exarch_core::ErrorCode;
use exarch_core::FfiErrorMessage;
use exarch_core::FfiKind;
use exarch_core::FfiSourceFault;
use exarch_core::IoKind;
use exarch_core::PartialOutcome;
use exarch_core::PolicySetting;
use exarch_core::Restore;
use exarch_core::SubCode;
use exarch_core::format_entry_path_for_error;
use exarch_core::sanitize_path_for_error;
use pyo3::PyTypeInfo;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::exceptions::PyFileExistsError;
use pyo3::exceptions::PyFileNotFoundError;
use pyo3::exceptions::PyOSError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyDict;
use pyo3::types::PyType;

use crate::warning::extraction_warnings;

// Base exception for all extraction errors
create_exception!(exarch, ArchiveError, PyException);

// Specific exception types
create_exception!(exarch, PathTraversalError, ArchiveError);
create_exception!(exarch, SymlinkEscapeError, ArchiveError);
create_exception!(exarch, HardlinkEscapeError, ArchiveError);
create_exception!(exarch, ZipBombError, ArchiveError);
create_exception!(exarch, InvalidPermissionsError, ArchiveError);
create_exception!(exarch, QuotaExceededError, ArchiveError);
create_exception!(exarch, SecurityViolationError, ArchiveError);
// Subclass of SecurityViolationError: raised when a ZIP archive's structure is
// read differently by different tools. Callers catching the parent still work.
create_exception!(exarch, ZipInconsistencyError, SecurityViolationError);
create_exception!(exarch, UnsupportedFormatError, ArchiveError);
// Subclass of UnsupportedFormatError: raised when the format cannot be
// identified at all (as opposed to being known but unsupported). Callers
// catching the parent still work.
create_exception!(exarch, UnknownFormatError, UnsupportedFormatError);
create_exception!(exarch, InvalidArchiveError, ArchiveError);

/// An exception class that derives from [`ArchiveError`] and from a builtin
/// exception, so `except OSError` and `except ValueError` handlers keep
/// working next to `except ArchiveError`.
///
/// `create_exception!` takes one base, so the class is built with
/// `type(name, bases, namespace)` on first use.
struct DualClass {
    name: &'static str,
    builtin: fn(Python<'_>) -> Bound<'_, PyType>,
    /// Attributes an instance may lack, so the class holds `None` for them.
    optional_attrs: &'static [&'static str],
    class: PyOnceLock<Py<PyType>>,
}

impl DualClass {
    const fn new(
        name: &'static str,
        builtin: fn(Python<'_>) -> Bound<'_, PyType>,
        optional_attrs: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            builtin,
            optional_attrs,
            class: PyOnceLock::new(),
        }
    }

    fn class<'py>(&self, py: Python<'py>) -> PyResult<&Bound<'py, PyType>> {
        self.class
            .get_or_try_init(py, || {
                let namespace = PyDict::new(py);
                namespace.set_item("__module__", "exarch")?;
                for attr in self.optional_attrs {
                    namespace.set_item(attr, py.None())?;
                }
                let bases = (py.get_type::<ArchiveError>(), (self.builtin)(py));
                PyType::type_object(py)
                    .call1((self.name, bases, namespace))?
                    .cast_into::<PyType>()
                    .map(Bound::unbind)
                    .map_err(PyErr::from)
            })
            .map(|class| class.bind(py))
    }

    fn error(&self, description: String) -> PyErr {
        Python::attach(|py| {
            self.class(py)
                .and_then(|class| class.call1((description,)))
                .map_or_else(|err| err, PyErr::from_value)
        })
    }
}

static OUTPUT_EXISTS: DualClass = DualClass::new(
    "OutputExistsError",
    PyFileExistsError::type_object,
    &["conflicts"],
);
static SOURCE_NOT_FOUND: DualClass =
    DualClass::new("SourceNotFoundError", PyFileNotFoundError::type_object, &[]);
static SOURCE_NOT_ACCESSIBLE: DualClass =
    DualClass::new("SourceNotAccessibleError", PyOSError::type_object, &[]);
static INVALID_CONFIGURATION: DualClass = DualClass::new(
    "InvalidConfigurationError",
    PyValueError::type_object,
    &["setting", "patterns"],
);
static INVALID_COMPRESSION_LEVEL: DualClass = DualClass::new(
    "InvalidCompressionLevelError",
    PyValueError::type_object,
    &[],
);

/// Every dual-base class, in registration order.
static DUAL_CLASSES: [&DualClass; 5] = [
    &OUTPUT_EXISTS,
    &SOURCE_NOT_FOUND,
    &SOURCE_NOT_ACCESSIBLE,
    &INVALID_CONFIGURATION,
    &INVALID_COMPRESSION_LEVEL,
];

/// Builds the Python exception for one error class from its message.
type NewErr = fn(String) -> PyErr;

fn new_base_error(description: String) -> PyErr {
    ArchiveError::new_err(description)
}

/// The exception class of each [`ErrorCode`] except `IoError`, which maps to
/// a builtin chosen by the I/O kind.
///
/// `None` only for a code added to the `#[non_exhaustive]` enum after this
/// match was written; `test_every_error_code_has_an_exception_class` rejects
/// that.
fn class_for(code: ErrorCode) -> Option<NewErr> {
    let ctor: NewErr = match code {
        ErrorCode::PathTraversal => |d| PathTraversalError::new_err(d),
        ErrorCode::SymlinkEscape => |d| SymlinkEscapeError::new_err(d),
        ErrorCode::HardlinkEscape => |d| HardlinkEscapeError::new_err(d),
        ErrorCode::ZipBomb => |d| ZipBombError::new_err(d),
        ErrorCode::ZipInconsistency => |d| ZipInconsistencyError::new_err(d),
        ErrorCode::InvalidPermissions => |d| InvalidPermissionsError::new_err(d),
        ErrorCode::QuotaExceeded => |d| QuotaExceededError::new_err(d),
        ErrorCode::SecurityViolation => |d| SecurityViolationError::new_err(d),
        ErrorCode::InvalidArchive => |d| InvalidArchiveError::new_err(d),
        ErrorCode::SourceNotFound => |d| SOURCE_NOT_FOUND.error(d),
        ErrorCode::SourceNotAccessible => |d| SOURCE_NOT_ACCESSIBLE.error(d),
        ErrorCode::OutputExists => |d| OUTPUT_EXISTS.error(d),
        ErrorCode::InvalidCompressionLevel => |d| INVALID_COMPRESSION_LEVEL.error(d),
        ErrorCode::InvalidConfiguration => |d| INVALID_CONFIGURATION.error(d),
        ErrorCode::UnknownFormat => |d| UnknownFormatError::new_err(d),
        ErrorCode::Cancelled => new_base_error,
        _ => return None,
    };
    Some(ctor)
}

/// Converts Rust extraction errors to Python exceptions.
///
/// The exception class, message and attached attributes all come from
/// [`CoreError::into_ffi_message`], so the mapping is written once in
/// `exarch-core`; this function only picks the Python class for each
/// [`FfiKind`].
///
/// This function is a workaround for Rust's orphan rules, which prevent
/// implementing `From<CoreError> for PyErr` directly.
pub fn convert_error(err: CoreError) -> PyErr {
    let os_error = os_error_fields(&err);
    let conflicts = destination_conflicts(&err);
    let patterns = unmatched_patterns(&err);
    let non_utf8_entry_path = non_utf8_entry_path(&err);
    let io_details = IoDetails::of(&err);
    let FfiErrorMessage {
        kind,
        description,
        partial,
        source_fault,
        ..
    } = err.into_ffi_message();
    let code = kind.code();
    let py_err = if let FfiKind::Io(io_kind) = kind {
        let err = io_error(io_kind, description);
        io_details.attach(&err);
        err
    } else {
        let err = class_for(kind.code()).unwrap_or(new_base_error)(description);
        if let Some(fault) = source_fault {
            set_os_error_fields(&err, &fault);
        }
        if let Some(fields) = os_error {
            set_errno_fields(&err, &fields);
        }
        set_optional_str(
            &err,
            "relaxable_by",
            kind.relaxable_by().map(PolicySetting::as_str),
        );
        set_optional_str(&err, "sub_code", kind.sub_code().map(SubCode::as_str));
        set_optional_str(
            &err,
            "setting",
            kind.setting().map(exarch_core::ConfigSetting::as_str),
        );
        set_attr(&err, "conflicts", conflicts);
        set_attr(&err, "patterns", patterns);
        set_attr(&err, "non_utf8_entry_path", non_utf8_entry_path);
        err
    };
    set_optional_str(&py_err, "code", Some(code.as_str()));
    if let Some(outcome) = partial {
        attach_partial(&py_err, outcome);
    }
    py_err
}

/// The builtin `OSError` of an I/O failure, carrying its stable `io_kind`.
///
/// `ErrorKind::OutOfMemory` becomes a plain `OSError` instead of the
/// `MemoryError` `PyO3` would pick, so every I/O failure is an `OSError`.
fn io_error(kind: std::io::ErrorKind, description: String) -> PyErr {
    let err = if kind == std::io::ErrorKind::OutOfMemory {
        PyOSError::new_err(description)
    } else {
        PyErr::from(std::io::Error::new(kind, description))
    };
    set_optional_str(&err, "io_kind", Some(IoKind::from(kind).as_str()));
    err
}

/// What a failed replace or a left-behind reservation tells beyond the I/O
/// kind: where the original destination, the staging directory or the empty
/// output file remain. Paths are redacted like those of an `Io` error.
#[derive(Default)]
struct IoDetails {
    restore: Option<&'static str>,
    backup: Option<String>,
    leftover: Option<String>,
    filename: Option<String>,
}

impl IoDetails {
    fn of(err: &CoreError) -> Self {
        match err {
            CoreError::ReplaceFailed(failure) => Self {
                restore: Some(match &failure.restore {
                    Restore::NotNeeded => "not_needed",
                    Restore::Restored => "restored",
                    _ => "failed",
                }),
                backup: match &failure.restore {
                    Restore::Failed { backup, .. } => Some(sanitize_path_for_error(backup)),
                    _ => None,
                },
                leftover: failure
                    .leftover
                    .as_ref()
                    .map(|leftover| sanitize_path_for_error(&leftover.path)),
                filename: None,
            },
            CoreError::OutputReservationLeft { .. } => Self {
                filename: err.redacted_path(),
                ..Self::default()
            },
            _ => Self::default(),
        }
    }

    fn attach(self, err: &PyErr) {
        set_optional_str(err, "restore", self.restore);
        set_attr(err, "backup", self.backup);
        set_attr(err, "leftover", self.leftover);
        set_attr(err, "filename", self.filename);
    }
}

/// The `errno` name and redacted file name of a refusal that is also a
/// builtin `OSError` (`FileNotFoundError`, `FileExistsError`).
struct OsErrorFields {
    errno: &'static str,
    filename: String,
}

fn os_error_fields(err: &CoreError) -> Option<OsErrorFields> {
    let errno = match err.ffi_kind() {
        FfiKind::SourceNotFound => "ENOENT",
        FfiKind::OutputExists => "EEXIST",
        _ => return None,
    };
    err.redacted_path()
        .map(|filename| OsErrorFields { errno, filename })
}

/// The archive-relative paths a `DestinationOccupied` refusal names.
fn destination_conflicts(err: &CoreError) -> Option<Vec<String>> {
    match err {
        CoreError::DestinationOccupied { conflicts, .. } => Some(
            conflicts
                .iter()
                .map(|path| format_entry_path_for_error(path))
                .collect(),
        ),
        CoreError::PartialExtraction(partial) => destination_conflicts(partial.cause()),
        _ => None,
    }
}

/// The include patterns an extraction found no entry for.
fn unmatched_patterns(err: &CoreError) -> Option<Vec<String>> {
    match err {
        CoreError::UnmatchedInclude { patterns } => {
            Some(patterns.iter().map(ToString::to_string).collect())
        }
        CoreError::PartialExtraction(partial) => unmatched_patterns(partial.cause()),
        _ => None,
    }
}

/// The injective rendering of the entry path a listing or in-memory extraction
/// refused for not being valid UTF-8.
fn non_utf8_entry_path(err: &CoreError) -> Option<String> {
    match err {
        CoreError::InvalidArchive(exarch_core::Malformation::EntryPathNotUtf8 { path }) => {
            Some(format_entry_path_for_error(path))
        }
        CoreError::PartialExtraction(partial) => non_utf8_entry_path(partial.cause()),
        _ => None,
    }
}

/// Sets `errno`, `strerror` and `filename` the way `open()` fills them for the
/// same failure.
fn set_errno_fields(err: &PyErr, fields: &OsErrorFields) {
    Python::attach(|py| {
        let fill = || -> PyResult<()> {
            let errno: i32 = py.import("errno")?.getattr(fields.errno)?.extract()?;
            let strerror = py.import("os")?.call_method1("strerror", (errno,))?;
            let value = err.value(py);
            value.setattr("errno", errno)?;
            value.setattr("strerror", strerror)?;
            value.setattr("filename", fields.filename.as_str())
        };
        // Best-effort, like the other attributes: the exception is raised
        // either way.
        let _ = fill();
    });
}

/// Sets `name` on the exception when `value` is present.
fn set_attr<T>(err: &PyErr, name: &str, value: Option<T>)
where
    for<'py> T: IntoPyObject<'py>,
{
    if let Some(value) = value {
        Python::attach(|py| {
            // setattr failures are silenced to preserve the `PyErr` signature.
            let _ = err.value(py).setattr(name, value);
        });
    }
}

/// Sets `name` on the exception when `value` is present; otherwise the class
/// default (`None`) stays visible.
fn set_optional_str(err: &PyErr, name: &str, value: Option<&'static str>) {
    if let Some(value) = value {
        Python::attach(|py| {
            // setattr failures are silenced to preserve the `PyErr` signature.
            let _ = err.value(py).setattr(name, value);
        });
    }
}

/// Sets `errno`, `strerror` and `filename` of an `OSError`-based exception from
/// an unreadable creation source, so `str(err)` names the file and the OS
/// error.
fn set_os_error_fields(err: &PyErr, fault: &FfiSourceFault) {
    Python::attach(|py| {
        let value = err.value(py);
        // setattr failures are silenced to preserve the `PyErr` signature.
        if let Some(errno) = fault.raw_os_error {
            let _ = value.setattr("errno", errno);
        }
        let _ = value.setattr("strerror", fault.text.as_str());
        let _ = value.setattr("filename", fault.name.as_str());
    });
}

/// Attaches `writes`, and while the writes remain on disk the report counters
/// (#210, #508), to the concrete exception of a partial extraction.
pub fn attach_partial(err: &PyErr, outcome: PartialOutcome) {
    Python::attach(|py| {
        let exc_value = err.value(py);
        // setattr failures are silenced to preserve the `PyErr` signature; the
        // workspace forbids unwrap/expect outside tests.
        let _ = exc_value.setattr("writes", outcome.writes().as_str());
        if let PartialOutcome::Kept(report) = outcome {
            let _ = exc_value.setattr("files_extracted", report.files_extracted);
            let _ = exc_value.setattr("bytes_written", report.bytes_written);
            let _ = exc_value.setattr("files_skipped", report.files_skipped());
            let _ = exc_value.setattr(
                "skipped",
                crate::report::PySkips::from(report.skipped.clone()),
            );
            if let Ok(warnings) = extraction_warnings(py, &report.warnings) {
                let _ = exc_value.setattr("warnings", warnings);
            }
        }
    });
}

/// Registers all exception types with the Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ArchiveError", m.py().get_type::<ArchiveError>())?;
    m.add(
        "PathTraversalError",
        m.py().get_type::<PathTraversalError>(),
    )?;
    m.add(
        "SymlinkEscapeError",
        m.py().get_type::<SymlinkEscapeError>(),
    )?;
    m.add(
        "HardlinkEscapeError",
        m.py().get_type::<HardlinkEscapeError>(),
    )?;
    m.add("ZipBombError", m.py().get_type::<ZipBombError>())?;
    m.add(
        "InvalidPermissionsError",
        m.py().get_type::<InvalidPermissionsError>(),
    )?;
    m.add(
        "QuotaExceededError",
        m.py().get_type::<QuotaExceededError>(),
    )?;
    let security_violation = m.py().get_type::<SecurityViolationError>();
    security_violation.setattr("relaxable_by", m.py().None())?;
    m.add(
        "ZipInconsistencyError",
        m.py().get_type::<ZipInconsistencyError>(),
    )?;
    m.add(
        "UnsupportedFormatError",
        m.py().get_type::<UnsupportedFormatError>(),
    )?;
    m.add(
        "UnknownFormatError",
        m.py().get_type::<UnknownFormatError>(),
    )?;
    security_violation.setattr("sub_code", m.py().None())?;
    m.add("SecurityViolationError", security_violation)?;
    let invalid_archive = m.py().get_type::<InvalidArchiveError>();
    invalid_archive.setattr("sub_code", m.py().None())?;
    invalid_archive.setattr("non_utf8_entry_path", m.py().None())?;
    m.add("InvalidArchiveError", invalid_archive)?;
    for dual in DUAL_CLASSES {
        m.add(dual.name, dual.class(m.py())?)?;
    }
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

    fn skipped(count: usize) -> exarch_core::Skips {
        let mut skips = exarch_core::Skips::default();
        for i in 0..count {
            let skip = exarch_core::Skip::new(exarch_core::SkipKind::Duplicate, format!("f{i}"));
            assert!(skips.record(skip).is_ok());
        }
        skips
    }

    #[test]
    fn test_every_error_code_has_an_exception_class() {
        for &code in ErrorCode::ALL {
            assert_eq!(
                class_for(code).is_none(),
                code == ErrorCode::IoError,
                "{code:?}"
            );
        }
    }

    /// One core error per dual-base class, with the builtin it must also be.
    fn dual_cases() -> Vec<(CoreError, &'static DualClass, &'static str)> {
        vec![
            (
                CoreError::OutputExists {
                    path: std::path::PathBuf::from("out.tar"),
                },
                &OUTPUT_EXISTS,
                "OUTPUT_EXISTS",
            ),
            (
                CoreError::SourceNotFound {
                    path: std::path::PathBuf::from("src"),
                },
                &SOURCE_NOT_FOUND,
                "SOURCE_NOT_FOUND",
            ),
            (
                CoreError::SourceNotAccessible {
                    path: std::path::PathBuf::from("src"),
                    error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                },
                &SOURCE_NOT_ACCESSIBLE,
                "SOURCE_NOT_ACCESSIBLE",
            ),
            (
                CoreError::InvalidConfiguration {
                    setting: exarch_core::ConfigSetting::MaxBytes,
                    problem: exarch_core::ConfigProblem::Zero,
                },
                &INVALID_CONFIGURATION,
                "INVALID_CONFIGURATION",
            ),
            (
                CoreError::InvalidCompressionLevel {
                    level: exarch_core::RequestedLevel::Integer(99),
                },
                &INVALID_COMPRESSION_LEVEL,
                "INVALID_COMPRESSION_LEVEL",
            ),
        ]
    }

    #[test]
    fn test_dual_classes_are_raised_with_code_and_both_bases() {
        pyo3::Python::initialize();
        for (err, dual, code) in dual_cases() {
            let py_err = convert_error(err);
            Python::attach(|py| {
                let class = dual.class(py).expect("class builds");
                assert!(py_err.matches(py, class).unwrap(), "{}", dual.name);
                assert!(
                    py_err.is_instance_of::<ArchiveError>(py),
                    "{} must derive from ArchiveError",
                    dual.name
                );
                let builtin = (dual.builtin)(py);
                assert!(py_err.matches(py, &builtin).unwrap(), "{}", dual.name);
                let raised: String = py_err
                    .value(py)
                    .getattr("code")
                    .expect("code missing")
                    .extract()
                    .expect("code not str");
                assert_eq!(raised, code);
            });
        }
    }

    #[test]
    fn test_every_dual_class_has_a_case() {
        assert_eq!(dual_cases().len(), DUAL_CLASSES.len());
    }

    #[test]
    fn test_io_error_carries_code() {
        pyo3::Python::initialize();
        let py_err = convert_error(CoreError::Io(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
        Python::attach(|py| {
            let raised: String = py_err
                .value(py)
                .getattr("code")
                .expect("code missing")
                .extract()
                .expect("code not str");
            assert_eq!(raised, "IO_ERROR");
        });
    }

    use exarch_core::Compressed;
    use exarch_core::PartialWrites;
    use exarch_core::QuotaResource as CoreQuotaResource;
    use exarch_core::Uncompressed;
    use std::path::PathBuf;

    /// Asserts the full attacker-supplied path is present in both debug and
    /// release builds — `PathTraversal` carries an archive-relative,
    /// attacker-authored path and is never redacted (see #462).
    #[test]
    fn test_path_traversal_conversion() {
        let err = CoreError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("path traversal"),
            "Expected 'path traversal' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("../etc/passwd"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    /// Asserts the full path is present in both debug and release builds —
    /// `SymlinkEscape` carries an archive-relative, attacker-authored path
    /// and is never redacted (see #462).
    #[test]
    fn test_symlink_escape_conversion() {
        let err = CoreError::SymlinkEscape {
            path: PathBuf::from("/etc/passwd"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("symlink target outside"),
            "Expected 'symlink target outside' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("/etc/passwd"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    /// Asserts the full path is present in both debug and release builds —
    /// `HardlinkEscape` carries an archive-relative, attacker-authored path
    /// and is never redacted (see #462).
    #[test]
    fn test_hardlink_escape_conversion() {
        let err = CoreError::HardlinkEscape {
            path: PathBuf::from("/etc/shadow"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("hardlink target outside"),
            "Expected 'hardlink target outside' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("/etc/shadow"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_zip_bomb_conversion() {
        let err = CoreError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("zip bomb"),
            "Expected 'zip bomb' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("1000"),
            "Expected compression ratio in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_zip_inconsistency_conversion() {
        let err = CoreError::ZipInconsistency(exarch_core::ZipInconsistency::OverlappingEntries);
        let py_err = convert_error(err);
        assert!(
            py_err.to_string().contains("overlap"),
            "Expected the finding in the error message, got: {py_err}"
        );
    }

    #[test]
    fn test_zip_bomb_unbounded_conversion() {
        let err = CoreError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(0),
            Uncompressed(10),
        ));
        let msg = convert_error(err).to_string();
        assert!(msg.contains("ratio: unbounded"), "got: {msg}");
    }

    #[test]
    fn test_invalid_permissions_conversion() {
        let err = CoreError::InvalidPermissions {
            path: PathBuf::from("malicious.sh"),
            mode: exarch_core::RawMode::new(0o777),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("invalid permissions"),
            "Expected 'invalid permissions' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("777"),
            "Expected permissions mode in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("malicious.sh"),
            "Expected filename in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_file_count_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("file count"),
            "Expected 'file count' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_total_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::TotalSize {
                current: 1_000_000,
                max: 500_000,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("total size"),
            "Expected 'total size' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_file_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileSize {
                size: 100_000_000,
                max: 50_000_000,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("single file size"),
            "Expected 'single file size' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_integer_overflow_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::IntegerOverflow,
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("integer overflow"),
            "Expected 'integer overflow' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_security_violation_conversion() {
        let err = CoreError::from(exarch_core::Violation::EncryptedEntry {
            name: "test violation".into(),
        });
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("security policy"),
            "Expected 'security policy' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("test violation"),
            "Expected reason in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_unknown_format_conversion() {
        let err = CoreError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("cannot determine archive format"),
            "Expected 'cannot determine archive format' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("archive.rar"),
            "Expected path in error message, got: {}",
            err_str
        );
        // UnknownFormatError must be the concrete type
        Python::attach(|py| {
            assert!(
                py_err.is_instance_of::<UnknownFormatError>(py),
                "expected UnknownFormatError, got: {}",
                py_err
            );
            // Must also be catchable as UnsupportedFormatError (subclass)
            assert!(
                py_err.is_instance_of::<UnsupportedFormatError>(py),
                "expected UnsupportedFormatError (parent), got: {}",
                py_err
            );
        });
    }

    #[test]
    fn test_invalid_archive_conversion() {
        let err = CoreError::from(exarch_core::Malformation::EntryNameUnreadable {
            index: None,
            detail: "corrupted header".into(),
        });
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("invalid archive"),
            "Expected 'invalid archive' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("corrupted header"),
            "Expected reason in error message, got: {}",
            err_str
        );
    }

    /// Asserts the original custom message is present, which only holds
    /// under `debug_assertions` (see `sanitize_io_error_for_error`).
    #[test]
    #[cfg(debug_assertions)]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = CoreError::Io(io_err);
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("file not found"),
            "Expected 'file not found' in error message, got: {}",
            err_str
        );
    }

    /// Regression test for #453 follow-up: in release builds, a
    /// host-derived path variant must be reduced to the filename, not leak
    /// the full host path. The redaction primitives themselves are tested
    /// directly in `exarch-core`'s redaction module; this exercises the
    /// binding's end-to-end `convert_error` path.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_source_not_found_strips_directory_in_release() {
        let err = CoreError::SourceNotFound {
            path: PathBuf::from("/srv/secret/app/x.txt"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("x.txt"),
            "Expected filename in error message, got: {}",
            err_str
        );
        assert!(
            !err_str.contains("/srv/secret"),
            "Expected host directory to be redacted, got: {}",
            err_str
        );
    }

    /// Regression test for #462: `PathTraversal`, `SymlinkEscape`, and
    /// `HardlinkEscape` carry archive-relative, attacker-authored paths and
    /// must keep the full path even in release builds, unlike genuinely
    /// host-derived path variants (see the test above).
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_attacker_path_variants_not_redacted_in_release() {
        let nested = PathBuf::from("nested/dir/../../etc/passwd");
        let variants = [
            CoreError::PathTraversal {
                path: nested.clone(),
            },
            CoreError::SymlinkEscape {
                path: nested.clone(),
            },
            CoreError::HardlinkEscape { path: nested },
        ];
        for err in variants {
            let err_str = convert_error(err).to_string();
            assert!(
                err_str.contains("nested/dir/../../etc/passwd"),
                "Expected full archive-relative path to survive redaction, got: {}",
                err_str
            );
        }
    }

    /// Regression test for #453 follow-up: `CoreError::Io` carries free-form
    /// messages (e.g. from `DestDir`'s validation) that can embed a host
    /// path. In release builds the message must be reduced to the
    /// `ErrorKind` description so no such path can leak through it.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_io_error_conversion_redacts_message_in_release() {
        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        );
        let err = CoreError::Io(io_err);
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            !err_str.contains("/srv/secret/app"),
            "Expected host path to be redacted, got: {}",
            err_str
        );
        assert!(
            err_str.contains("permission denied"),
            "Expected ErrorKind description in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_source_not_found_conversion() {
        pyo3::Python::initialize();
        let err = CoreError::SourceNotFound {
            path: PathBuf::from("missing_source.tar.gz"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("No such file or directory"),
            "Expected the errno text in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("missing_source.tar.gz"),
            "Expected filename in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_register_exceptions_adds_all_types() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "test_module").expect("Failed to create test module");
            register_exceptions(&module.as_borrowed()).expect("Failed to register exceptions");

            // Verify all exception types are registered
            assert!(
                module.getattr("ArchiveError").is_ok(),
                "ArchiveError not registered"
            );
            assert!(
                module.getattr("PathTraversalError").is_ok(),
                "PathTraversalError not registered"
            );
            assert!(
                module.getattr("SymlinkEscapeError").is_ok(),
                "SymlinkEscapeError not registered"
            );
            assert!(
                module.getattr("HardlinkEscapeError").is_ok(),
                "HardlinkEscapeError not registered"
            );
            assert!(
                module.getattr("ZipBombError").is_ok(),
                "ZipBombError not registered"
            );
            assert!(
                module.getattr("InvalidPermissionsError").is_ok(),
                "InvalidPermissionsError not registered"
            );
            assert!(
                module.getattr("QuotaExceededError").is_ok(),
                "QuotaExceededError not registered"
            );
            assert!(
                module.getattr("SecurityViolationError").is_ok(),
                "SecurityViolationError not registered"
            );
            assert!(
                module.getattr("ZipInconsistencyError").is_ok(),
                "ZipInconsistencyError not registered"
            );
            assert!(
                module.getattr("UnsupportedFormatError").is_ok(),
                "UnsupportedFormatError not registered"
            );
            assert!(
                module.getattr("UnknownFormatError").is_ok(),
                "UnknownFormatError not registered"
            );
            assert!(
                module.getattr("InvalidArchiveError").is_ok(),
                "InvalidArchiveError not registered"
            );
        });
    }

    /// Regression test for #251 + #210: `convert_error` must surface the
    /// specific exception type from the inner source and attach
    /// `files_extracted` and `bytes_written` attributes for the
    /// partial-extraction report.
    #[test]
    fn test_partial_extraction_preserves_specific_type_with_report() {
        use exarch_core::ExtractionReport;
        use exarch_core::QuotaResource;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 3;
            r.bytes_written = 1024;
            r
        };
        let source = CoreError::QuotaExceeded {
            resource: QuotaResource::FileCount { current: 4, max: 3 },
        };
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            source,
            report,
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        Python::attach(|py| {
            // Must be the specific concrete type.
            assert!(
                py_err.is_instance_of::<QuotaExceededError>(py),
                "expected QuotaExceededError, got: {}",
                py_err
            );
            // Report attributes must be present on the concrete exception.
            let exc_value = py_err.value(py);
            let files: u64 = exc_value
                .getattr("files_extracted")
                .expect("files_extracted missing")
                .extract()
                .expect("files_extracted not u64");
            let bytes: u64 = exc_value
                .getattr("bytes_written")
                .expect("bytes_written missing")
                .extract()
                .expect("bytes_written not u64");
            assert_eq!(files, 3);
            assert_eq!(bytes, 1024);
        });
    }

    /// Regression test for #508: `convert_error` must also attach
    /// `files_skipped` and `warnings` from the partial-extraction report,
    /// alongside the pre-existing `files_extracted`/`bytes_written`. Uses a
    /// skip-only report (`files_extracted: 0, bytes_written: 0`) matching
    /// #505's original trigger — a failure that skipped entries without
    /// extracting anything — and a typed warning, so the test documents why
    /// the fix exists, not just that the fields are forwarded.
    #[test]
    fn test_partial_extraction_includes_files_skipped_and_warnings() {
        use exarch_core::ExtractionReport;
        use exarch_core::QuotaResource;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 0;
            r.bytes_written = 0;
            r.skipped = skipped(2);
            r.warnings = vec![exarch_core::ExtractionWarning::AntiItemsSkipped { count: 2 }];
            r
        };
        let source = CoreError::QuotaExceeded {
            resource: QuotaResource::FileCount { current: 4, max: 3 },
        };
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            source,
            report,
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        Python::attach(|py| {
            let exc_value = py_err.value(py);
            let files_skipped: usize = exc_value
                .getattr("files_skipped")
                .expect("files_skipped missing")
                .extract()
                .expect("files_skipped not usize");
            let warnings = exc_value.getattr("warnings").expect("warnings missing");
            assert_eq!(files_skipped, 2);
            assert_eq!(warnings.len().expect("a list"), 1);
            let warning = warnings.get_item(0).expect("one warning");
            let (kind, message, count): (String, String, u64) = (
                warning.getattr("kind").unwrap().extract().unwrap(),
                warning.getattr("message").unwrap().extract().unwrap(),
                warning.getattr("count").unwrap().extract().unwrap(),
            );
            assert_eq!(kind, "anti_items_skipped");
            assert_eq!(
                message,
                "skipped 2 7z anti-items (deletion markers are not applied)"
            );
            assert_eq!(count, 2);
        });
    }

    /// Regression test for #747: a rolled-back atomic run attaches `writes`
    /// but none of the counters that would read as files left on disk.
    #[test]
    fn test_partial_extraction_rolled_back_omits_counters() {
        use exarch_core::ExtractionReport;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 2;
            r.bytes_written = 2;
            r
        };
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            CoreError::SymlinkEscape {
                path: PathBuf::from("ln"),
            },
            report,
            PartialWrites::RolledBack,
        ));

        let py_err = convert_error(err);
        Python::attach(|py| {
            assert!(py_err.is_instance_of::<SymlinkEscapeError>(py));
            let exc_value = py_err.value(py);
            let writes: String = exc_value
                .getattr("writes")
                .expect("writes missing")
                .extract()
                .expect("writes not str");
            assert_eq!(writes, "rolled_back");
            for attr in [
                "files_extracted",
                "bytes_written",
                "files_skipped",
                "warnings",
            ] {
                assert!(
                    exc_value.getattr(attr).is_err(),
                    "{attr} must be absent after rollback"
                );
            }
        });
    }

    #[test]
    fn test_partial_extraction_kept_attaches_writes() {
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            CoreError::SymlinkEscape {
                path: PathBuf::from("ln"),
            },
            exarch_core::ExtractionReport::default(),
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        Python::attach(|py| {
            let writes: String = py_err
                .value(py)
                .getattr("writes")
                .expect("writes missing")
                .extract()
                .expect("writes not str");
            assert_eq!(writes, "kept");
        });
    }

    // Regression tests for #251: security error variants must surface their
    // specific type and carry the #210 report attributes.
    //
    // Helper that verifies the given `py_err` from a PartialExtraction is
    // the expected specific type and has the expected report attributes.
    fn assert_partial_extraction_report<T: pyo3::PyTypeInfo>(
        py_err: &PyErr,
        expected_files: usize,
        expected_bytes: u64,
    ) {
        Python::attach(|py| {
            assert!(
                py_err.is_instance_of::<T>(py),
                "expected specific error type, got: {}",
                py_err
            );
            let exc_value = py_err.value(py);
            let files: usize = exc_value
                .getattr("files_extracted")
                .expect("files_extracted missing")
                .extract()
                .expect("files_extracted extraction failed");
            let bytes: u64 = exc_value
                .getattr("bytes_written")
                .expect("bytes_written missing")
                .extract()
                .expect("bytes_written extraction failed");
            assert_eq!(files, expected_files, "files_extracted mismatch");
            assert_eq!(bytes, expected_bytes, "bytes_written mismatch");
        });
    }

    #[test]
    fn test_partial_extraction_symlink_escape_preserves_type_and_report() {
        use exarch_core::ExtractionReport;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 2;
            r.bytes_written = 512;
            r
        };
        let source = CoreError::SymlinkEscape {
            path: PathBuf::from("/etc/passwd"),
        };
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            source,
            report,
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        assert_partial_extraction_report::<SymlinkEscapeError>(&py_err, 2, 512);
    }

    #[test]
    fn test_partial_extraction_hardlink_escape_preserves_type_and_report() {
        use exarch_core::ExtractionReport;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 2;
            r.bytes_written = 512;
            r
        };
        let source = CoreError::HardlinkEscape {
            path: PathBuf::from("/etc/shadow"),
        };
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            source,
            report,
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        assert_partial_extraction_report::<HardlinkEscapeError>(&py_err, 2, 512);
    }

    #[test]
    fn test_partial_extraction_security_violation_preserves_type_and_report() {
        use exarch_core::ExtractionReport;

        let report = {
            let mut r = ExtractionReport::new();
            r.files_extracted = 2;
            r.bytes_written = 512;
            r
        };
        let source = CoreError::from(exarch_core::Violation::EncryptedArchive);
        let err = CoreError::PartialExtraction(exarch_core::Partial::new(
            source,
            report,
            PartialWrites::Kept,
        ));

        let py_err = convert_error(err);
        assert_partial_extraction_report::<SecurityViolationError>(&py_err, 2, 512);
    }

    fn attr_str(err: &PyErr, name: &str) -> Option<String> {
        Python::attach(|py| {
            err.value(py)
                .getattr(name)
                .ok()
                .and_then(|value| value.extract().ok())
        })
    }

    #[test]
    fn test_io_error_carries_io_kind_and_out_of_memory_is_an_oserror() {
        pyo3::Python::initialize();
        for (kind, expected) in [
            (std::io::ErrorKind::PermissionDenied, "PermissionDenied"),
            (std::io::ErrorKind::StorageFull, "StorageFull"),
            (std::io::ErrorKind::OutOfMemory, "OutOfMemory"),
        ] {
            let py_err = convert_error(CoreError::Io(std::io::Error::from(kind)));
            Python::attach(|py| {
                assert!(
                    py_err.is_instance_of::<PyOSError>(py),
                    "{kind:?} must be an OSError"
                );
            });
            assert_eq!(attr_str(&py_err, "io_kind").as_deref(), Some(expected));
            assert_eq!(attr_str(&py_err, "code").as_deref(), Some("IO_ERROR"));
        }
    }

    #[test]
    fn test_source_not_found_and_output_exists_carry_os_error_fields() {
        pyo3::Python::initialize();
        let cases = [
            (
                CoreError::SourceNotFound {
                    path: PathBuf::from("dir/nothere"),
                },
                2_i32,
            ),
            (
                CoreError::OutputExists {
                    path: PathBuf::from("dir/ex.tar"),
                },
                17,
            ),
        ];
        for (err, errno) in cases {
            let filename = err.redacted_path();
            let py_err = convert_error(err);
            Python::attach(|py| {
                let value = py_err.value(py);
                let raised: i32 = value.getattr("errno").unwrap().extract().unwrap();
                assert_eq!(raised, errno);
                let name: String = value.getattr("filename").unwrap().extract().unwrap();
                assert_eq!(Some(name), filename);
                let strerror: String = value.getattr("strerror").unwrap().extract().unwrap();
                assert!(!strerror.is_empty());
            });
        }
    }

    #[test]
    fn test_destination_occupied_names_its_conflicts() {
        pyo3::Python::initialize();
        let err = CoreError::DestinationOccupied {
            destination: PathBuf::from("/srv/out"),
            conflicts: vec![PathBuf::from("a/b.txt")].into_boxed_slice(),
        };
        let py_err = convert_error(err);
        Python::attach(|py| {
            let class = OUTPUT_EXISTS.class(py).unwrap();
            assert!(py_err.matches(py, class).unwrap());
            let conflicts: Vec<String> = py_err
                .value(py)
                .getattr("conflicts")
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(conflicts, vec!["a/b.txt"]);
        });
        assert_eq!(attr_str(&py_err, "code").as_deref(), Some("OUTPUT_EXISTS"));
    }

    #[test]
    fn test_non_utf8_entry_path_is_attached() {
        pyo3::Python::initialize();
        let err = CoreError::from(exarch_core::Malformation::EntryPathNotUtf8 {
            path: PathBuf::from("a/b.txt"),
        });
        let py_err = convert_error(err);
        assert_eq!(
            attr_str(&py_err, "non_utf8_entry_path").as_deref(),
            Some("a/b.txt")
        );
    }

    #[test]
    fn test_replace_failed_reports_restore_and_backup() {
        use exarch_core::ReplaceFailure;

        pyo3::Python::initialize();
        let failure = ReplaceFailure::new(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            Restore::Failed {
                backup: PathBuf::from("dir/.backup"),
                error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
            None,
        );
        let py_err = convert_error(CoreError::ReplaceFailed(failure));

        Python::attach(|py| assert!(py_err.is_instance_of::<PyOSError>(py)));
        assert_eq!(
            attr_str(&py_err, "io_kind").as_deref(),
            Some("PermissionDenied")
        );
        assert_eq!(attr_str(&py_err, "restore").as_deref(), Some("failed"));
        assert_eq!(
            attr_str(&py_err, "backup"),
            Some(sanitize_path_for_error(std::path::Path::new("dir/.backup")))
        );
        assert_eq!(attr_str(&py_err, "leftover"), None);
    }

    #[test]
    fn test_output_reservation_left_names_the_file() {
        pyo3::Python::initialize();
        let err = CoreError::OutputReservationLeft {
            path: PathBuf::from("out/archive.tar"),
            error: std::io::Error::from(std::io::ErrorKind::StorageFull),
        };
        let expected = err.redacted_path();
        let py_err = convert_error(err);

        assert_eq!(attr_str(&py_err, "filename"), expected);
        assert_eq!(attr_str(&py_err, "io_kind").as_deref(), Some("StorageFull"));
    }
}
