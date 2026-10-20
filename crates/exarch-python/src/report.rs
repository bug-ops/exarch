//! Python bindings for report types.

use exarch_core::ExtractionReport as CoreExtractionReport;
use exarch_core::creation::CreationReport as CoreCreationReport;
use exarch_core::inspection::manifest::ArchiveEntry;
use exarch_core::inspection::manifest::ArchiveManifest;
use exarch_core::inspection::manifest::ManifestEntryType;
use exarch_core::inspection::report::VerificationIssue;
use exarch_core::inspection::report::VerificationReport;
use pyo3::prelude::*;

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
/// * `files_skipped` - Number of files skipped due to security checks
/// * `warnings` - List of warning messages
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

    /// Number of files skipped due to security checks.
    #[getter]
    fn files_skipped(&self) -> usize {
        self.inner.files_skipped
    }

    /// Returns a copy of the warning messages list.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the warnings multiple times, cache the result in a local variable.
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
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
            self.inner.files_skipped,
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
/// * `warnings` - List of warning messages
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
        self.inner.files_skipped
    }

    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
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
            self.inner.files_skipped,
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
#[pyclass(name = "ArchiveEntry")]
#[derive(Clone)]
pub struct PyArchiveEntry {
    inner: ArchiveEntry,
}

#[pymethods]
impl PyArchiveEntry {
    #[getter]
    fn path(&self) -> String {
        self.inner.path.to_string_lossy().into_owned()
    }

    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    #[getter]
    fn entry_type(&self) -> String {
        self.inner.kind.entry_type().as_str().to_owned()
    }

    #[getter]
    fn is_symlink(&self) -> bool {
        self.inner.kind.entry_type() == ManifestEntryType::Symlink
    }

    #[getter]
    fn is_hardlink(&self) -> bool {
        self.inner.kind.entry_type() == ManifestEntryType::Hardlink
    }

    #[getter]
    fn compressed_size(&self) -> Option<u64> {
        self.inner.compressed_size()
    }

    #[getter]
    fn mode(&self) -> Option<u32> {
        self.inner.mode
    }

    #[getter]
    fn symlink_target(&self) -> Option<String> {
        self.inner
            .kind
            .symlink_target()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[getter]
    fn hardlink_target(&self) -> Option<String> {
        self.inner
            .kind
            .hardlink_target()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn compression_ratio(&self) -> Option<f64> {
        self.inner.compression_ratio()
    }

    fn __str__(&self) -> String {
        format!(
            "ArchiveEntry(path='{}', type={}, size={})",
            self.inner.path.display(),
            self.inner.kind.entry_type(),
            self.inner.size
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<ArchiveEntry> for PyArchiveEntry {
    fn from(inner: ArchiveEntry) -> Self {
        Self { inner }
    }
}

/// Archive manifest with entry metadata.
///
/// # Attributes
///
/// * `total_entries` - Total number of entries
/// * `total_size` - Total uncompressed size
/// * `entries` - List of archive entries
#[pyclass(name = "ArchiveManifest")]
#[derive(Clone)]
pub struct PyArchiveManifest {
    inner: ArchiveManifest,
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
    fn entries(&self) -> Vec<PyArchiveEntry> {
        self.inner
            .entries()
            .iter()
            .cloned()
            .map(PyArchiveEntry::from)
            .collect()
    }

    #[getter]
    fn format(&self) -> String {
        self.inner.format().as_str().to_owned()
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

impl From<ArchiveManifest> for PyArchiveManifest {
    fn from(inner: ArchiveManifest) -> Self {
        Self { inner }
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
    fn severity(&self) -> String {
        self.inner.severity.as_str().to_owned()
    }

    #[getter]
    fn message(&self) -> String {
        self.inner.message.clone()
    }

    #[getter]
    fn path(&self) -> Option<String> {
        self.inner
            .entry_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[getter]
    fn category(&self) -> String {
        self.inner.category.as_str().to_owned()
    }

    #[getter]
    fn context(&self) -> Option<String> {
        self.inner.context.clone()
    }

    fn __str__(&self) -> String {
        format!("[{}] {}", self.inner.severity, self.inner.message)
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
    fn status(&self) -> String {
        self.inner.status().as_str().to_owned()
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
    fn integrity_status(&self) -> String {
        self.inner.integrity_status().as_str().to_owned()
    }

    #[getter]
    fn security_status(&self) -> String {
        self.inner.security_status().as_str().to_owned()
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
    use exarch_core::inspection::manifest::ManifestEntryKind;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_properties() {
        let mut core_report = CoreExtractionReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.files_skipped = 1;
        core_report.add_warning("Test warning".to_string());

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
            py_report.warnings().len(),
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
            py_report.warnings().len(),
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

    #[test]
    fn test_warnings_clone_behavior() {
        let mut core_report = CoreExtractionReport::new();
        core_report.add_warning("Warning 1".to_string());
        core_report.add_warning("Warning 2".to_string());

        let py_report = PyExtractionReport::from(core_report);

        // Get warnings twice to verify clone behavior
        let warnings1 = py_report.warnings();
        let warnings2 = py_report.warnings();

        assert_eq!(warnings1.len(), 2, "First call should return 2 warnings");
        assert_eq!(
            warnings2.len(),
            2,
            "Second call should also return 2 warnings"
        );
        assert_eq!(warnings1, warnings2, "Both calls should return equal lists");
    }

    #[test]
    fn test_creation_report_properties() {
        use exarch_core::creation::CreationReport;

        let mut core_report = CreationReport::new();
        core_report.files_added = 20;
        core_report.directories_added = 10;
        core_report.symlinks_added = 3;
        core_report.bytes_written = 2048;
        core_report.bytes_compressed = 1024;
        core_report.duration = Duration::from_millis(750);
        core_report.files_skipped = 2;
        core_report.add_warning("Skipped file".to_string());

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
        use exarch_core::creation::CreationReport;

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
        use std::path::PathBuf;

        let mut entry =
            ArchiveEntry::new(PathBuf::from("test/file.txt"), ManifestEntryKind::File, 512);
        entry.compression = exarch_core::EntryCompression::Entry(256);
        entry.mode = Some(0o644);

        let py_entry = PyArchiveEntry::from(entry);

        assert_eq!(py_entry.path(), "test/file.txt", "path should match");
        assert_eq!(py_entry.size(), 512, "size should be 512");
        assert_eq!(py_entry.entry_type(), "File", "entry_type should be File");
        assert!(!py_entry.is_symlink(), "should not be symlink");
        assert!(!py_entry.is_hardlink(), "should not be hardlink");
        assert_eq!(
            py_entry.compressed_size(),
            Some(256),
            "compressed_size should be Some(256)"
        );
        assert_eq!(py_entry.mode(), Some(0o644), "mode should be Some(0o644)");
        assert_eq!(
            py_entry.compression_ratio(),
            Some(2.0),
            "compression ratio should be 2.0"
        );
    }

    #[test]
    fn test_archive_entry_symlink() {
        use std::path::PathBuf;

        let entry = ArchiveEntry::new(
            PathBuf::from("link"),
            ManifestEntryKind::Symlink {
                target: Some(PathBuf::from("target/file.txt")),
            },
            0,
        );

        let py_entry = PyArchiveEntry::from(entry);

        assert!(py_entry.is_symlink(), "should be symlink");
        assert!(!py_entry.is_hardlink(), "should not be hardlink");
        assert_eq!(
            py_entry.symlink_target(),
            Some("target/file.txt".to_string()),
            "symlink_target should match"
        );
    }

    #[test]
    fn test_archive_entry_hardlink() {
        use std::path::PathBuf;

        let entry = ArchiveEntry::new(
            PathBuf::from("hardlink"),
            ManifestEntryKind::Hardlink {
                target: Some(PathBuf::from("original/file.txt")),
            },
            0,
        );

        let py_entry = PyArchiveEntry::from(entry);

        assert!(!py_entry.is_symlink(), "should not be symlink");
        assert!(py_entry.is_hardlink(), "should be hardlink");
        assert_eq!(
            py_entry.hardlink_target(),
            Some("original/file.txt".to_string()),
            "hardlink_target should match"
        );
    }

    #[test]
    fn test_archive_manifest_properties() {
        use exarch_core::formats::detect::ArchiveType;
        use std::path::PathBuf;

        let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
        for (name, size) in [("file1.txt", 100), ("file2.txt", 200)] {
            let entry = ArchiveEntry::new(PathBuf::from(name), ManifestEntryKind::File, size);
            manifest.add_entry(entry).unwrap();
        }

        let py_manifest = PyArchiveManifest::from(manifest);

        assert_eq!(py_manifest.total_entries(), 2, "total_entries should be 2");
        assert_eq!(py_manifest.total_size(), 300, "total_size should be 300");
        assert_eq!(
            py_manifest.entries().len(),
            2,
            "entries should have 2 items"
        );
        // Format display varies, just check it's not empty
        assert!(
            !py_manifest.format().is_empty(),
            "format should not be empty"
        );
    }

    #[test]
    fn test_verification_issue_security_policy_category() {
        use exarch_core::inspection::report::IssueCategory;
        use exarch_core::inspection::report::IssueSeverity;

        let issue = VerificationIssue::new(
            IssueSeverity::High,
            IssueCategory::SecurityPolicy,
            "Security violation: symlinks not allowed".to_string(),
        );

        assert_eq!(
            PyVerificationIssue::from(issue).category(),
            "Security Policy"
        );
    }

    #[test]
    fn test_verification_issue_properties() {
        use exarch_core::inspection::report::IssueCategory;
        use exarch_core::inspection::report::IssueSeverity;
        use std::path::PathBuf;

        let mut issue = VerificationIssue::new(
            IssueSeverity::Critical,
            IssueCategory::PathTraversal,
            "Path traversal detected".to_string(),
        );
        issue.entry_path = Some(PathBuf::from("../etc/passwd"));
        issue.context = Some("Entry attempts to escape extraction directory".to_string());

        let py_issue = PyVerificationIssue::from(issue);

        assert_eq!(
            py_issue.severity(),
            "CRITICAL",
            "severity() forwards IssueSeverity's Display impl, which renders upper-case \
             (matches exarch-cli and exarch-node's own convention)"
        );
        assert_eq!(
            py_issue.message(),
            "Path traversal detected",
            "message should match"
        );
        assert_eq!(
            py_issue.path(),
            Some("../etc/passwd".to_string()),
            "path should match"
        );
        assert_eq!(
            py_issue.category(),
            "Path Traversal",
            "category() forwards IssueCategory's Display impl (matches exarch-cli's JSON output \
             and exarch-node's own convention)"
        );
        assert!(py_issue.context().is_some(), "context should be Some");
    }

    fn literal_line<T: Copy>(alias: &str, all: &[T], as_str: fn(T) -> &'static str) -> String {
        let values: Vec<String> = all.iter().map(|v| format!("\"{}\"", as_str(*v))).collect();
        format!("{alias} = Literal[{}]", values.join(", "))
    }

    #[test]
    fn test_pyi_literal_aliases_match_core_enums() {
        use exarch_core::formats::detect::ArchiveType;
        use exarch_core::inspection::CheckStatus;
        use exarch_core::inspection::IssueCategory;
        use exarch_core::inspection::IssueSeverity;
        use exarch_core::inspection::VerificationStatus;

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
        ];
        for line in expected {
            assert!(
                pyi.lines()
                    .any(|l| l.split("  # ").next() == Some(line.as_str())),
                "exarch.pyi is out of sync with exarch-core, expected line:\n{line}"
            );
        }
    }

    // NOTE: VerificationReport tests removed as they depend on types that may
    // not be public in core. The type wrappers are tested via Python
    // integration tests.
}
