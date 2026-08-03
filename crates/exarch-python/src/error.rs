//! Python exception types for archive extraction errors.

use exarch_core::ArchiveError as CoreError;
use exarch_core::QuotaResource as CoreQuotaResource;
use exarch_core::format_entry_path_for_error;
use exarch_core::sanitize_io_error_for_error;
use exarch_core::sanitize_path_for_error;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::exceptions::PyIOError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

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
create_exception!(exarch, UnsupportedFormatError, ArchiveError);
// Subclass of UnsupportedFormatError: raised when the format cannot be
// identified at all (as opposed to being known but unsupported). Callers
// catching the parent still work.
create_exception!(exarch, UnknownFormatError, UnsupportedFormatError);
create_exception!(exarch, InvalidArchiveError, ArchiveError);

/// Converts Rust extraction errors to Python exceptions.
///
/// This preserves error context and maps each Rust error variant to the
/// appropriate Python exception type.
///
/// This function is a workaround for Rust's orphan rules, which prevent
/// implementing `From<CoreError> for PyErr` directly.
pub fn convert_error(err: CoreError) -> PyErr {
    match err {
        CoreError::PathTraversal { path } => {
            let path_str = format_entry_path_for_error(&path);
            PathTraversalError::new_err(format!("path traversal detected: {path_str}"))
        }
        CoreError::SymlinkEscape { path } => {
            let path_str = format_entry_path_for_error(&path);
            SymlinkEscapeError::new_err(format!(
                "symlink target outside extraction directory: {path_str}"
            ))
        }
        CoreError::HardlinkEscape { path } => {
            let path_str = format_entry_path_for_error(&path);
            HardlinkEscapeError::new_err(format!(
                "hardlink target outside extraction directory: {path_str}"
            ))
        }
        CoreError::ZipBomb {
            compressed,
            uncompressed,
            ratio,
        } => ZipBombError::new_err(format!(
            "potential zip bomb: compressed={compressed} bytes, uncompressed={uncompressed} bytes (ratio: {ratio:.2})"
        )),
        CoreError::InvalidPermissions { path, mode } => {
            let path_str = format_entry_path_for_error(&path);
            InvalidPermissionsError::new_err(format!(
                "invalid permissions for {path_str}: {mode:#o}"
            ))
        }
        CoreError::QuotaExceeded { resource } => {
            let msg = match resource {
                CoreQuotaResource::FileCount { current, max } => {
                    format!("quota exceeded: file count ({current} > {max})")
                }
                CoreQuotaResource::TotalSize { current, max } => {
                    format!("quota exceeded: total size ({current} > {max})")
                }
                CoreQuotaResource::FileSize { size, max } => {
                    format!("quota exceeded: file size ({size} > {max})")
                }
                CoreQuotaResource::IntegerOverflow => {
                    "quota exceeded: integer overflow in quota tracking".to_string()
                }
            };
            QuotaExceededError::new_err(msg)
        }
        CoreError::SecurityViolation { reason } => SecurityViolationError::new_err(format!(
            "operation denied by security policy: {reason}"
        )),
        CoreError::InvalidArchive(msg) => {
            InvalidArchiveError::new_err(format!("invalid archive: {msg}"))
        }
        CoreError::Io(e) => {
            let msg = sanitize_io_error_for_error(&e);
            PyErr::from(std::io::Error::new(e.kind(), msg))
        }
        CoreError::SourceNotFound { path } => {
            let path_str = sanitize_path_for_error(&path);
            PyIOError::new_err(format!("source path not found: {path_str}"))
        }
        CoreError::SourceNotAccessible { path } => {
            let path_str = sanitize_path_for_error(&path);
            PyIOError::new_err(format!("source path is not accessible: {path_str}"))
        }
        CoreError::OutputExists { path } => {
            let path_str = sanitize_path_for_error(&path);
            PyIOError::new_err(format!("output file already exists: {path_str}"))
        }
        CoreError::InvalidCompressionLevel { level } => {
            PyValueError::new_err(format!("invalid compression level {level}, must be 1-9"))
        }
        CoreError::UnknownFormat { path } => {
            let path_str = sanitize_path_for_error(&path);
            UnknownFormatError::new_err(format!("cannot determine archive format from: {path_str}"))
        }
        CoreError::InvalidConfiguration { reason } => {
            PyValueError::new_err(format!("invalid configuration: {reason}"))
        }
        CoreError::PartialExtraction { source, report } => {
            // Recover the specific exception type (SymlinkEscapeError, HardlinkEscapeError,
            // etc.) so callers can catch the precise error. The partial-extraction report
            // attributes from #210 are attached to that concrete exception instead.
            let source_err = convert_error(*source);
            Python::attach(|py| {
                let exc_value = source_err.value(py);
                // setattr failures are silenced to preserve the `PyErr → PyErr` signature;
                // the workspace forbids unwrap/expect outside tests.
                let _ = exc_value.setattr("files_extracted", report.files_extracted);
                let _ = exc_value.setattr("bytes_written", report.bytes_written);
                source_err
            })
        }
    }
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
    m.add(
        "SecurityViolationError",
        m.py().get_type::<SecurityViolationError>(),
    )?;
    m.add(
        "UnsupportedFormatError",
        m.py().get_type::<UnsupportedFormatError>(),
    )?;
    m.add(
        "UnknownFormatError",
        m.py().get_type::<UnknownFormatError>(),
    )?;
    m.add(
        "InvalidArchiveError",
        m.py().get_type::<InvalidArchiveError>(),
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
        let err = CoreError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
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
    fn test_invalid_permissions_conversion() {
        let err = CoreError::InvalidPermissions {
            path: PathBuf::from("malicious.sh"),
            mode: 0o777,
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
            err_str.contains("file size"),
            "Expected 'file size' in error message, got: {}",
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
        let err = CoreError::SecurityViolation {
            reason: "test violation".to_string(),
        };
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
        let err = CoreError::InvalidArchive("corrupted header".to_string());
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
    /// directly in `exarch_core::error::redaction`; this exercises the
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
            CoreError::HardlinkEscape {
                path: nested.clone(),
            },
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
        let err = CoreError::SourceNotFound {
            path: PathBuf::from("missing_source.tar.gz"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("source path not found"),
            "Expected 'source path not found' in error message, got: {}",
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

        let report = ExtractionReport {
            files_extracted: 3,
            bytes_written: 1024,
            ..ExtractionReport::default()
        };
        let source = CoreError::QuotaExceeded {
            resource: QuotaResource::FileCount { current: 4, max: 3 },
        };
        let err = CoreError::PartialExtraction {
            source: Box::new(source),
            report,
        };

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

        let report = ExtractionReport {
            files_extracted: 2,
            bytes_written: 512,
            ..ExtractionReport::default()
        };
        let source = CoreError::SymlinkEscape {
            path: PathBuf::from("/etc/passwd"),
        };
        let err = CoreError::PartialExtraction {
            source: Box::new(source),
            report,
        };

        let py_err = convert_error(err);
        assert_partial_extraction_report::<SymlinkEscapeError>(&py_err, 2, 512);
    }

    #[test]
    fn test_partial_extraction_hardlink_escape_preserves_type_and_report() {
        use exarch_core::ExtractionReport;

        let report = ExtractionReport {
            files_extracted: 2,
            bytes_written: 512,
            ..ExtractionReport::default()
        };
        let source = CoreError::HardlinkEscape {
            path: PathBuf::from("/etc/shadow"),
        };
        let err = CoreError::PartialExtraction {
            source: Box::new(source),
            report,
        };

        let py_err = convert_error(err);
        assert_partial_extraction_report::<HardlinkEscapeError>(&py_err, 2, 512);
    }

    #[test]
    fn test_partial_extraction_security_violation_preserves_type_and_report() {
        use exarch_core::ExtractionReport;

        let report = ExtractionReport {
            files_extracted: 2,
            bytes_written: 512,
            ..ExtractionReport::default()
        };
        let source = CoreError::SecurityViolation {
            reason: "test policy violation".to_string(),
        };
        let err = CoreError::PartialExtraction {
            source: Box::new(source),
            report,
        };

        let py_err = convert_error(err);
        assert_partial_extraction_report::<SecurityViolationError>(&py_err, 2, 512);
    }

    /// Regression test for #463: `convert_error` binds `path` per match arm
    /// and calls the redaction algorithm directly (S2 fix) rather than
    /// going through `ArchiveError::redacted_path()`, so nothing at compile
    /// time keeps the two mappings in sync. Cross-checks every path-carrying
    /// variant's `convert_error` output against `redacted_path()` so the two
    /// independently-maintained mappings (this file's and core's) cannot
    /// silently drift apart.
    #[test]
    fn test_convert_error_paths_agree_with_redacted_path_dispatcher() {
        let path = PathBuf::from("some/example/path.txt");
        let variants: Vec<CoreError> = vec![
            CoreError::PathTraversal { path: path.clone() },
            CoreError::SymlinkEscape { path: path.clone() },
            CoreError::HardlinkEscape { path: path.clone() },
            CoreError::InvalidPermissions {
                path: path.clone(),
                mode: 0o644,
            },
            CoreError::SourceNotFound { path: path.clone() },
            CoreError::SourceNotAccessible { path: path.clone() },
            CoreError::OutputExists { path: path.clone() },
            CoreError::UnknownFormat { path },
        ];

        for err in variants {
            let expected = err
                .redacted_path()
                .expect("variant is known to carry a path");
            let err_str = convert_error(err).to_string();
            assert!(
                err_str.contains(&expected),
                "convert_error output does not agree with ArchiveError::redacted_path(): \
                 expected {expected:?} in {err_str:?}"
            );
        }
    }
}
