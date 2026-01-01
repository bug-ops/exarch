"""
Memory-safe archive extraction library with security validation.

This module provides secure archive extraction, creation, listing, and verification
with built-in protection against path traversal, zip bombs, symlink attacks,
and other common vulnerabilities.
"""

from pathlib import Path
from typing import Callable

__version__: str

class SecurityConfig:
    """
    Security configuration for archive extraction.

    All security features default to deny (secure-by-default policy).
    """

    def __init__(self) -> None:
        """Creates a new SecurityConfig with secure defaults."""
        ...

    @staticmethod
    def default() -> SecurityConfig:
        """Creates a SecurityConfig with secure defaults."""
        ...

    @staticmethod
    def permissive() -> SecurityConfig:
        """
        Creates a permissive configuration for trusted archives.

        Enables: symlinks, hardlinks, absolute paths, world-writable files.
        Use only for archives from trusted sources.
        """
        ...

    def max_file_size(self, size: int) -> SecurityConfig:
        """Sets the maximum file size in bytes."""
        ...

    def max_total_size(self, size: int) -> SecurityConfig:
        """Sets the maximum total size in bytes."""
        ...

    def max_compression_ratio(self, ratio: float) -> SecurityConfig:
        """Sets the maximum compression ratio."""
        ...

    def max_file_count(self, count: int) -> SecurityConfig:
        """Sets the maximum file count."""
        ...

    def max_path_depth(self, depth: int) -> SecurityConfig:
        """Sets the maximum path depth."""
        ...

    def allow_symlinks(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies symlinks."""
        ...

    def allow_hardlinks(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies hardlinks."""
        ...

    def allow_absolute_paths(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies absolute paths."""
        ...

    def allow_world_writable(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies world-writable files."""
        ...

    def preserve_permissions(self, preserve: bool = True) -> SecurityConfig:
        """Sets whether to preserve permissions from archive."""
        ...

    def add_allowed_extension(self, ext: str) -> SecurityConfig:
        """Adds an allowed file extension."""
        ...

    def add_banned_component(self, component: str) -> SecurityConfig:
        """Adds a banned path component."""
        ...

    def build(self) -> SecurityConfig:
        """Finalizes the configuration."""
        ...

    def is_path_component_allowed(self, component: str) -> bool:
        """Checks if a path component is allowed."""
        ...

    def is_extension_allowed(self, extension: str) -> bool:
        """Checks if a file extension is allowed."""
        ...

class CreationConfig:
    """
    Configuration for archive creation.

    Controls how archives are created from filesystem sources.
    """

    def __init__(self) -> None:
        """Creates a new CreationConfig with default settings."""
        ...

    @staticmethod
    def default() -> CreationConfig:
        """Creates a CreationConfig with default settings."""
        ...

    def compression_level(self, level: int) -> CreationConfig:
        """Sets the compression level (1-9)."""
        ...

    def preserve_permissions(self, preserve: bool = True) -> CreationConfig:
        """Sets whether to preserve permissions."""
        ...

    def follow_symlinks(self, follow: bool = True) -> CreationConfig:
        """Sets whether to follow symlinks."""
        ...

    def include_hidden(self, include: bool = True) -> CreationConfig:
        """Sets whether to include hidden files."""
        ...

    def exclude_patterns(self, patterns: list[str]) -> CreationConfig:
        """Sets exclude patterns."""
        ...

    def max_file_size(self, size: int | None) -> CreationConfig:
        """Sets maximum file size in bytes."""
        ...

    def build(self) -> CreationConfig:
        """Finalizes the configuration."""
        ...

class ExtractionReport:
    """
    Report of an archive extraction operation.

    Contains statistics and metadata about the extraction process.
    """

    @property
    def files_extracted(self) -> int:
        """Number of files successfully extracted."""
        ...

    @property
    def directories_created(self) -> int:
        """Number of directories created."""
        ...

    @property
    def symlinks_created(self) -> int:
        """Number of symlinks created."""
        ...

    @property
    def bytes_written(self) -> int:
        """Total bytes written to disk."""
        ...

    @property
    def duration_ms(self) -> int:
        """Extraction duration in milliseconds."""
        ...

    @property
    def files_skipped(self) -> int:
        """Number of files skipped due to security checks."""
        ...

    @property
    def warnings(self) -> list[str]:
        """List of warning messages."""
        ...

    def total_items(self) -> int:
        """Returns total number of items processed."""
        ...

    def has_warnings(self) -> bool:
        """Returns whether any warnings were generated."""
        ...

class CreationReport:
    """
    Report of an archive creation operation.

    Contains statistics and metadata about the creation process.
    """

    @property
    def files_added(self) -> int:
        """Number of files added."""
        ...

    @property
    def directories_added(self) -> int:
        """Number of directories added."""
        ...

    @property
    def symlinks_added(self) -> int:
        """Number of symlinks added."""
        ...

    @property
    def bytes_written(self) -> int:
        """Total uncompressed bytes."""
        ...

    @property
    def bytes_compressed(self) -> int:
        """Total compressed bytes."""
        ...

    @property
    def duration_ms(self) -> int:
        """Creation duration in milliseconds."""
        ...

    @property
    def files_skipped(self) -> int:
        """Number of files skipped."""
        ...

    @property
    def warnings(self) -> list[str]:
        """List of warning messages."""
        ...

    def total_items(self) -> int:
        """Returns total number of items added."""
        ...

    def has_warnings(self) -> bool:
        """Returns whether any warnings were generated."""
        ...

    def compression_ratio(self) -> float:
        """Returns the compression ratio (uncompressed / compressed)."""
        ...

    def compression_percentage(self) -> float:
        """Returns the compression percentage (space saved)."""
        ...

class ArchiveEntry:
    """Single entry in archive manifest."""

    @property
    def path(self) -> str:
        """Entry path."""
        ...

    @property
    def size(self) -> int:
        """Uncompressed size in bytes."""
        ...

    @property
    def entry_type(self) -> str:
        """Entry type (File, Directory, Symlink, Hardlink)."""
        ...

    @property
    def is_symlink(self) -> bool:
        """Whether this is a symlink."""
        ...

    @property
    def is_hardlink(self) -> bool:
        """Whether this is a hardlink."""
        ...

    @property
    def compressed_size(self) -> int | None:
        """Compressed size in bytes (if available)."""
        ...

    @property
    def mode(self) -> int | None:
        """File permissions (Unix mode)."""
        ...

    @property
    def symlink_target(self) -> str | None:
        """Symlink target (if applicable)."""
        ...

    @property
    def hardlink_target(self) -> str | None:
        """Hardlink target (if applicable)."""
        ...

    def compression_ratio(self) -> float | None:
        """Returns the compression ratio if compressed size is available."""
        ...

class ArchiveManifest:
    """
    Archive manifest with entry metadata.

    Generated by list_archive(), contains metadata about all entries
    without extracting them to disk.
    """

    @property
    def total_entries(self) -> int:
        """Total number of entries."""
        ...

    @property
    def total_size(self) -> int:
        """Total uncompressed size."""
        ...

    @property
    def entries(self) -> list[ArchiveEntry]:
        """List of archive entries."""
        ...

    @property
    def format(self) -> str:
        """Archive format."""
        ...

class VerificationIssue:
    """Verification issue."""

    @property
    def severity(self) -> str:
        """Issue severity level."""
        ...

    @property
    def message(self) -> str:
        """Human-readable description."""
        ...

    @property
    def path(self) -> str | None:
        """Entry path that triggered issue (if applicable)."""
        ...

    @property
    def category(self) -> str:
        """Issue category."""
        ...

    @property
    def context(self) -> str | None:
        """Optional context."""
        ...

class VerificationReport:
    """
    Verification report.

    Generated by verify_archive(), contains security and integrity checks
    performed without extracting files to disk.
    """

    @property
    def status(self) -> str:
        """Overall verification status."""
        ...

    @property
    def issues(self) -> list[VerificationIssue]:
        """List of issues found."""
        ...

    @property
    def total_entries(self) -> int:
        """Total entries scanned."""
        ...

    @property
    def total_size(self) -> int:
        """Total uncompressed size."""
        ...

    @property
    def integrity_status(self) -> str:
        """Integrity check result."""
        ...

    @property
    def security_status(self) -> str:
        """Security check result."""
        ...

    def is_safe(self) -> bool:
        """Returns true if the archive is safe (no critical or high severity issues)."""
        ...

    def has_critical_issues(self) -> bool:
        """Returns true if there are any critical severity issues."""
        ...

def extract_archive(
    archive_path: str | Path,
    output_dir: str | Path,
    config: SecurityConfig | None = None,
) -> ExtractionReport:
    """
    Extract an archive to the specified directory.

    This function provides secure archive extraction with configurable
    security policies. By default, it uses a restrictive security
    configuration that blocks symlinks, hardlinks, absolute paths, and
    enforces resource quotas.

    Args:
        archive_path: Path to the archive file (str or pathlib.Path)
        output_dir: Directory where files will be extracted (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)

    Returns:
        ExtractionReport with extraction statistics

    Raises:
        ValueError: Invalid argument type, null bytes in path, or path too long
        PathTraversalError: Path traversal attempt detected
        SymlinkEscapeError: Symlink points outside extraction directory
        HardlinkEscapeError: Hardlink target outside extraction directory
        ZipBombError: Potential zip bomb detected
        InvalidPermissionsError: File permissions are invalid or unsafe
        QuotaExceededError: Resource quota exceeded
        SecurityViolationError: Security policy violation
        UnsupportedFormatError: Archive format not supported
        InvalidArchiveError: Archive is corrupted
        IOError: I/O operation failed
    """
    ...

def create_archive(
    output_path: str | Path,
    sources: list[str | Path],
    config: CreationConfig | None = None,
) -> CreationReport:
    """
    Create an archive from source files and directories.

    Args:
        output_path: Path to output archive file (str or pathlib.Path)
        sources: List of source files/directories to include (str or pathlib.Path)
        config: Optional CreationConfig (uses defaults if None)

    Returns:
        CreationReport with creation statistics

    Raises:
        ValueError: Invalid arguments
        IOError: I/O operation failed
        UnsupportedFormatError: Archive format not supported
    """
    ...

ProgressCallbackFn = Callable[[str, int, int, int], None]
"""Progress callback: (path, total, current, bytes_written) -> None."""

def create_archive_with_progress(
    output_path: str | Path,
    sources: list[str | Path],
    config: CreationConfig | None = None,
    progress: ProgressCallbackFn | None = None,
) -> CreationReport:
    """
    Create an archive with progress reporting.

    Args:
        output_path: Path to output archive file (str or pathlib.Path)
        sources: List of source files/directories to include (str or pathlib.Path)
        config: Optional CreationConfig (uses defaults if None)
        progress: Optional callback function for progress updates

    Returns:
        CreationReport with creation statistics

    Raises:
        ValueError: Invalid arguments
        IOError: I/O operation failed
        UnsupportedFormatError: Archive format not supported

    Example:
        >>> def progress(path: str, total: int, current: int, bytes: int):
        ...     print(f"{current}/{total}: {path} ({bytes} bytes)")
        >>> report = create_archive_with_progress("output.tar.gz", ["src/"], None, progress)
    """
    ...

def list_archive(
    archive_path: str | Path,
    config: SecurityConfig | None = None,
) -> ArchiveManifest:
    """
    List archive contents without extracting.

    Args:
        archive_path: Path to archive file (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)

    Returns:
        ArchiveManifest with entry metadata

    Raises:
        ValueError: Invalid arguments
        IOError: I/O operation failed
        UnsupportedFormatError: Archive format not supported
    """
    ...

def verify_archive(
    archive_path: str | Path,
    config: SecurityConfig | None = None,
) -> VerificationReport:
    """
    Verify archive integrity and security.

    Args:
        archive_path: Path to archive file (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)

    Returns:
        VerificationReport with validation results

    Raises:
        ValueError: Invalid arguments
        IOError: I/O operation failed
        UnsupportedFormatError: Archive format not supported
    """
    ...

class PathTraversalError(ValueError):
    """Path traversal attempt detected."""

    ...

class SymlinkEscapeError(ValueError):
    """Symlink points outside extraction directory."""

    ...

class HardlinkEscapeError(ValueError):
    """Hardlink target outside extraction directory."""

    ...

class ZipBombError(ValueError):
    """Potential zip bomb detected."""

    ...

class InvalidPermissionsError(ValueError):
    """File permissions are invalid or unsafe."""

    ...

class QuotaExceededError(ValueError):
    """Resource quota exceeded."""

    ...

class SecurityViolationError(ValueError):
    """Security policy violation."""

    ...

class UnsupportedFormatError(ValueError):
    """Archive format not supported."""

    ...

class InvalidArchiveError(ValueError):
    """Archive is corrupted."""

    ...
