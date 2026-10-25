"""
Memory-safe archive extraction library with security validation.

This module provides secure archive extraction, creation, listing, and verification
with built-in protection against path traversal, zip bombs, symlink attacks,
and other common vulnerabilities.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Literal

__version__: str

# Stub-only aliases: the native module does not export them at runtime.
_ArchiveType = Literal["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip", "SevenZ"]
_ManifestEntryType = Literal["File", "Directory", "Symlink", "Hardlink"]
_VerificationStatus = Literal["PASS", "FAIL", "WARNING"]
_CheckStatus = Literal["OK", "FAILED", "WARNING", "SKIPPED"]
_IntegrityStatus = Literal["OK", "FAILED", "INCOMPLETE", "SKIPPED"]
_UnverifiedReason = Literal["over_budget", "resource_limit", "solid_policy", "size_ceiling", "uncovered_block_crc", "not_decodable", "no_end_marker", "path_too_long", "descriptor_tail"]  # noqa: E501  # fmt: skip
_IssueSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_IssueCategory = Literal["Path Traversal", "Symlink Escape", "Hardlink Escape", "Zip Bomb", "Invalid Permissions", "Quota Exceeded", "Security Policy", "Invalid Archive", "Suspicious Path", "Executable File", "Corrupt Data", "Integrity Incomplete", "Header Mismatch", "Duplicate Entry", "Overlapping Entries", "Hidden Entry", "Name Collision", "Archive Note"]  # noqa: E501  # fmt: skip
_ZipConsistency = Literal["enforce", "ignore"]

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

    def with_max_file_size(self, size: int) -> SecurityConfig:
        """Sets the maximum file size in bytes."""
        ...

    def with_max_total_size(self, size: int) -> SecurityConfig:
        """Sets the maximum total size in bytes."""
        ...

    def with_max_compression_ratio(self, ratio: float) -> SecurityConfig:
        """Sets the maximum compression ratio.

        Solid 7z blocks are exempt: each block is checked as a whole against a
        fixed 1000x limit that is configurable only from the Rust API.
        """
        ...

    def with_max_file_count(self, count: int) -> SecurityConfig:
        """
        Sets the maximum file count.

        `extract_archive` counts files, symlinks and hardlinks, not
        directories; `list_archive` and `verify_archive` count every entry.
        """
        ...

    def with_max_path_depth(self, depth: int) -> SecurityConfig:
        """Sets the maximum path depth."""
        ...

    def with_allow_symlinks(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies symlinks."""
        ...

    def with_allow_hardlinks(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies hardlinks."""
        ...

    def with_allow_absolute_paths(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies absolute paths."""
        ...

    def with_allow_world_writable(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies world-writable files."""
        ...

    def with_allow_solid_archives(self, allow: bool = True) -> SecurityConfig:
        """Allows or denies solid 7z archives."""
        ...

    def with_parallel_decode_memory(self, size: int | None) -> SecurityConfig:
        """
        Sets the memory in bytes for decoding 7z LZMA2 runs ahead on worker threads.

        ``None`` decodes on one thread. The default is 128 MiB (1 GiB for
        ``permissive()``). A stock 7-Zip archive has 64 MiB runs and needs about
        100 MiB per extra concurrent run. A valid archive decodes to the same bytes
        either way and a corrupt one fails the same file. Each call may start up to
        16 worker threads and hold its own lookahead, so concurrent calls multiply
        both.

        Raises:
            ValueError: If ``size`` is zero, negative or above 2**64 - 1.
        """
        ...

    def with_zip_consistency(self, policy: _ZipConsistency) -> SecurityConfig:
        """
        Sets how ZIP archives with ambiguous structure are handled.

        ``"enforce"`` (the default, also for ``permissive()``) rejects archives whose
        local and central headers disagree, that repeat a name, overlap entries or hide
        records. ``"ignore"`` keeps the central directory interpretation without
        structural findings. Raises ``ValueError`` for any other string.
        """
        ...

    def with_max_solid_block_memory(self, size: int) -> SecurityConfig:
        """
        Sets the maximum memory budget in bytes for decompressing a solid 7z block.

        Only enforced when ``with_allow_solid_archives`` is called with ``True``. Raises
        ``ValueError`` if *size* is zero.
        """
        ...

    def with_preserve_permissions(self, preserve: bool = True) -> SecurityConfig:
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

    @property
    def max_file_size(self) -> int:
        """Maximum size for a single file in bytes (default: 50 MB)."""
        ...

    @max_file_size.setter
    def max_file_size(self, value: int) -> None: ...
    @property
    def max_total_size(self) -> int:
        """Maximum total size for all files in bytes (default: 500 MB)."""
        ...

    @max_total_size.setter
    def max_total_size(self, value: int) -> None: ...
    @property
    def max_compression_ratio(self) -> float:
        """Maximum compression ratio allowed (default: 100.0).

        Not applied to solid 7z blocks, which use a fixed 1000x limit.
        """
        ...

    @max_compression_ratio.setter
    def max_compression_ratio(self, value: float) -> None: ...
    @property
    def max_file_count(self) -> int:
        """
        Maximum number of entries (default: 10,000).

        `extract_archive` counts files, symlinks and hardlinks, not
        directories; `list_archive` and `verify_archive` count every entry.
        """
        ...

    @max_file_count.setter
    def max_file_count(self, value: int) -> None: ...
    @property
    def max_path_depth(self) -> int:
        """Maximum path depth allowed (default: 32)."""
        ...

    @max_path_depth.setter
    def max_path_depth(self, value: int) -> None: ...
    @property
    def preserve_permissions(self) -> bool:
        """Whether to preserve file permissions from archive (default: False)."""
        ...

    @preserve_permissions.setter
    def preserve_permissions(self, value: bool) -> None: ...
    @property
    def max_solid_block_memory(self) -> int:
        """Maximum memory budget in bytes for decompressing a solid 7z block (default: 512 MB)."""
        ...

    @max_solid_block_memory.setter
    def max_solid_block_memory(self, value: int) -> None: ...
    @property
    def allow_symlinks(self) -> bool:
        """Whether symlinks are allowed (default: False)."""
        ...

    @property
    def allow_hardlinks(self) -> bool:
        """Whether hardlinks are allowed (default: False)."""
        ...

    @property
    def allow_absolute_paths(self) -> bool:
        """Whether absolute paths are allowed (default: False)."""
        ...

    @property
    def allow_world_writable(self) -> bool:
        """Whether world-writable files are allowed (default: False)."""
        ...

    @property
    def parallel_decode_memory(self) -> int | None:
        """Lookahead bytes for parallel 7z LZMA2 decoding, or ``None`` (default: 128 MiB)."""
        ...

    @parallel_decode_memory.setter
    def parallel_decode_memory(self, value: int | None) -> None: ...
    @property
    def zip_consistency(self) -> _ZipConsistency:
        """How ZIP archives with ambiguous structure are handled (default: ``"enforce"``)."""
        ...

    @zip_consistency.setter
    def zip_consistency(self, value: _ZipConsistency) -> None: ...
    @property
    def allow_solid_archives(self) -> bool:
        """Whether solid 7z archives are allowed (default: False)."""
        ...

    @property
    def allowed_extensions(self) -> list[str]:
        """List of allowed file extensions (empty = allow all)."""
        ...

    @allowed_extensions.setter
    def allowed_extensions(self, value: list[str]) -> None: ...
    @property
    def banned_path_components(self) -> list[str]:
        """List of banned path components."""
        ...

    @banned_path_components.setter
    def banned_path_components(self, value: list[str]) -> None: ...

class VerificationOptions:
    """
    Options controlling verification behavior (non-security).

    By default ``verify_archive`` checks metadata only and reports
    ``integrity_status`` as ``"SKIPPED"``. ``with_integrity_check`` also decodes
    the payload to the decoder's EOF so checksums and codec framing are
    verified.
    """

    def __init__(self) -> None:
        """Creates a new VerificationOptions with defaults (no integrity check)."""
        ...

    @staticmethod
    def default() -> VerificationOptions:
        """Creates a VerificationOptions with defaults."""
        ...

    def with_integrity_check(self, budget: int | None = None) -> VerificationOptions:
        """
        Enables the payload integrity check.

        Args:
            budget: Extra bytes the check may decode beyond listing. ``None``
                uses the default of 500 MiB, which does not follow
                ``max_total_size``.

        Raises:
            ValueError: ``budget`` is zero or negative.
        """
        ...

    @property
    def integrity_check(self) -> bool:
        """Whether the payload integrity check is enabled (default: False)."""
        ...

    @property
    def decompression_budget(self) -> int | None:
        """Budget in bytes when the integrity check is enabled, else None."""
        ...

class ExtractionOptions:
    """
    Options controlling extraction behavior (non-security).

    Separate from SecurityConfig to keep security settings focused.
    These options control operational behavior such as duplicate handling.
    """

    def __init__(self) -> None:
        """Creates a new ExtractionOptions with defaults."""
        ...

    @staticmethod
    def default() -> ExtractionOptions:
        """Creates an ExtractionOptions with defaults."""
        ...

    def with_skip_duplicates(self, skip: bool = True) -> ExtractionOptions:
        """
        Sets whether duplicate archive entries are skipped silently.

        When ``True`` (default), duplicate entries produce a warning in the
        report. When ``False``, a duplicate entry causes an error.
        """
        ...

    def with_atomic(self, atomic: bool = True) -> ExtractionOptions:
        """
        Sets whether extraction uses a temporary directory for atomic commits.

        When ``True``, files are extracted to a temp dir in the same parent as
        the output directory, then atomically renamed on completion. On failure
        the temp dir is removed, leaving the output directory untouched.
        Default: ``False``.

        **Important:** atomic mode requires that the output directory does not
        already exist. If it does, extraction raises ``OutputExistsError``.
        Non-atomic mode extracts into an existing directory without error.
        """
        ...

    def build(self) -> ExtractionOptions:
        """Finalizes the configuration."""
        ...

    @property
    def skip_duplicates(self) -> bool:
        """Whether to skip duplicate entries silently (default: True)."""
        ...

    @skip_duplicates.setter
    def skip_duplicates(self, value: bool) -> None: ...
    @property
    def atomic(self) -> bool:
        """Whether atomic extraction is enabled (default: False)."""
        ...

    @atomic.setter
    def atomic(self, value: bool) -> None: ...

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

    def with_compression_level(self, level: int) -> CreationConfig:
        """Sets the compression level (1-9)."""
        ...

    def with_preserve_permissions(self, preserve: bool = True) -> CreationConfig:
        """Sets whether to preserve permissions."""
        ...

    def with_follow_symlinks(self, follow: bool = True) -> CreationConfig:
        """Sets whether to follow symlinks."""
        ...

    def with_include_hidden(self, include: bool = True) -> CreationConfig:
        """Sets whether to include hidden files."""
        ...

    def with_exclude_patterns(self, patterns: list[str]) -> CreationConfig:
        """Sets exclude patterns."""
        ...

    def with_max_file_size(self, size: int | None) -> CreationConfig:
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
    def entry_type(self) -> _ManifestEntryType:
        """Entry type."""
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
        """
        Compressed size in bytes (if available).

        For the first file of a solid 7z block this is the whole block's
        compressed size; other solid members report None.
        """
        ...

    @property
    def mode(self) -> int | None:
        """File permissions (Unix mode)."""
        ...

    @property
    def symlink_target(self) -> str | None:
        """
        Symlink target (if applicable).

        None for a 7z symlink: listing does not decode 7z entry data to read it.
        """
        ...

    @property
    def hardlink_target(self) -> str | None:
        """Hardlink target (if applicable)."""
        ...

    def compression_ratio(self) -> float | None:
        """
        Returns the compression ratio if the entry owns its compressed data.

        None for TAR, empty entries and solid 7z members (including the
        block start, whose ratio is checked per block).
        """
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
    def format(self) -> _ArchiveType:
        """Archive format."""
        ...

class VerificationIssue:
    """Verification issue."""

    @property
    def severity(self) -> _IssueSeverity:
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
    def category(self) -> _IssueCategory:
        """Issue category."""
        ...

    @property
    def context(self) -> str | None:
        """Optional context."""
        ...

class UnverifiedEntry:
    """One entry the integrity check could not verify."""

    @property
    def path(self) -> str:
        """Entry path inside the archive."""
        ...

    @property
    def reason(self) -> _UnverifiedReason:
        """Why the entry was not verified."""
        ...

class IntegrityGaps:
    """What a requested integrity check left unverified."""

    @property
    def counts(self) -> dict[_UnverifiedReason, int]:
        """Unverified items per reason; reasons with no items are absent."""
        ...

    @property
    def entries(self) -> list[UnverifiedEntry]:
        """Unverified entries listed by path, up to a fixed cap (see ``omitted``)."""
        ...

    @property
    def omitted(self) -> int:
        """Unverified entries with a path that did not fit ``entries``."""
        ...

    @property
    def total(self) -> int:
        """Total number of unverified items, including those without a path."""
        ...

class VerificationReport:
    """
    Verification report.

    Generated by verify_archive(), contains the result of the security checks
    performed without extracting files to disk.
    Payload integrity is checked only when requested with
    ``VerificationOptions().with_integrity_check()``; otherwise
    ``integrity_status`` is ``"SKIPPED"``.
    """

    @property
    def status(self) -> _VerificationStatus:
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
    def integrity_status(self) -> _IntegrityStatus:
        """
        Payload integrity result.

        ``"SKIPPED"`` unless requested. ``"FAILED"`` means a checksum or decoder
        error proved the payload corrupt. ``"INCOMPLETE"`` means part of the
        payload was not verified (budget, resource limit, solid 7z archive while
        ``allow_solid_archives`` is off, TAR without an end-of-archive marker);
        it comes with a Medium issue, so ``status`` is at least ``"WARNING"``.
        ``"OK"`` means every payload byte was decoded and every checksum the
        format has matched; plain TAR, 7z entries without CRC and zstd frames
        without a content checksum carry no payload checksum, so ``"OK"`` there
        means complete and decodable. "Decode to EOF" means the decoder's EOF:
        every gzip member, bzip2 stream, xz stream and zstd frame is decoded;
        an all-zero tail is accepted, other trailing bytes are an error.
        """
        ...

    @property
    def integrity_gaps(self) -> IntegrityGaps | None:
        """
        What the integrity check left unverified.

        ``None`` unless the check was requested; an empty ``IntegrityGaps``
        (``total == 0``) when everything was verified. The counts, the listed
        entries and the ``Integrity Incomplete`` issue message come from the
        same data.
        """
        ...

    @property
    def security_status(self) -> _CheckStatus:
        """Security check result."""
        ...

    def is_safe(self) -> bool:
        """Returns true if the archive is safe (no Medium-or-higher severity issues)."""
        ...

    def has_critical_issues(self) -> bool:
        """Returns true if there are any critical severity issues."""
        ...

ProgressCallbackFn = Callable[[str, int, int, int], None]
"""Progress callback: (path, total, current, bytes_written) -> None."""

def extract_archive(
    archive_path: str | Path,
    output_dir: str | Path,
    config: SecurityConfig | None = None,
    options: ExtractionOptions | None = None,
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
        ValueError: Invalid argument type
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

    Note:
        When extraction fails after some files have already been written to disk,
        the specific exception (e.g. ``SymlinkEscapeError``) is raised with
        ``files_extracted``, ``bytes_written``, ``files_skipped``, and
        ``warnings`` attributes attached. Detect a partial extraction via
        ``hasattr(e, "files_extracted")`` — but see
        ``extract_archive_with_progress`` below: a raising ``progress`` callback
        over an otherwise-successful extraction attaches ``files_extracted`` and
        ``bytes_written`` (not ``files_skipped``/``warnings``), distinguished by
        a ``progress_callback_error`` marker attribute this function's own
        exceptions never carry.
    """
    ...

def extract_archive_with_progress(
    archive_path: str | Path,
    output_dir: str | Path,
    config: SecurityConfig | None = None,
    progress: ProgressCallbackFn | None = None,
    options: ExtractionOptions | None = None,
) -> ExtractionReport:
    """
    Extract an archive to the specified directory with progress reporting.

    Args:
        archive_path: Path to the archive file (str or pathlib.Path)
        output_dir: Directory where files will be extracted (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)
        progress: Optional callback function for progress updates

    Returns:
        ExtractionReport with extraction statistics

    Raises:
        ValueError: Invalid argument type
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

    Note:
        When a progress callback is provided, the GIL is held during extraction
        so that the callback can safely call into Python. Without a callback,
        the GIL is released for performance.

        Progress callback limitations:

        - The ``bytes_written`` argument reflects ``on_bytes_written`` events
          from the core library. Extraction does not emit byte-level progress,
          only entry-level events, so ``bytes_written`` will always be 0 during
          extraction.
        - For TAR-family formats (tar, tar.gz, tar.bz2, tar.xz, tar.zst) the
          ``total`` argument is 0 because the entry count is unknown until the
          stream is fully read.

        When extraction fails after some files have already been written to disk,
        the specific exception (e.g. ``SymlinkEscapeError``) is raised with
        ``files_extracted``, ``bytes_written``, ``files_skipped``, and
        ``warnings`` attributes attached.

        If ``progress`` itself raises, extraction is **not** aborted early — the
        underlying progress-callback contract has no cancellation signal, so
        extraction always runs to completion first, and ``progress`` is not
        called again for the remaining entries once it has raised:

        - If extraction otherwise succeeds, ``progress``'s own exception is what
          propagates (unchanged — the same type, message, and traceback), with
          ``files_extracted`` and ``bytes_written`` attributes attached
          describing what was written, plus a ``progress_callback_error = True``
          marker attribute. Check ``progress_callback_error`` before treating the
          presence of ``files_extracted`` as a partial-extraction signal — see
          the note on ``extract_archive`` above.
        - If extraction also fails, the extraction error takes priority (a
          raising ``progress`` can never mask a security error such as
          ``SymlinkEscapeError``) and ``progress``'s exception is attached as
          ``__cause__`` rather than being dropped.

    Example:
        >>> def progress(path: str, total: int, current: int, bytes: int):
        ...     print(f"{current}/{total}: {path} ({bytes} bytes)")
        >>> report = extract_archive_with_progress("archive.tar.gz", "/tmp/out", None, progress)
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

    Note:
        If ``progress`` itself raises, creation is **not** aborted early — the
        underlying progress-callback contract has no cancellation signal, so
        creation always runs to completion first, and ``progress`` is not
        called again for the remaining entries once it has raised:

        - If creation otherwise succeeds, ``progress``'s own exception is what
          propagates (unchanged — the same type, message, and traceback), with
          ``files_added`` and ``bytes_written`` attributes attached describing
          what was written, plus a ``progress_callback_error = True`` marker
          attribute.
        - If creation also fails, the creation error takes priority (a raising
          ``progress`` can never mask a security error such as
          ``SymlinkEscapeError``) and ``progress``'s exception is attached as
          ``__cause__`` rather than being dropped.

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
    options: VerificationOptions | None = None,
) -> VerificationReport:
    """
    Verify archive security, optionally checking payload integrity.

    Args:
        archive_path: Path to archive file (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)
        options: Optional VerificationOptions; pass
            ``VerificationOptions().with_integrity_check()`` to decode the
            payload and verify checksums

    Returns:
        VerificationReport with validation results

    Raises:
        ValueError: Invalid arguments
        IOError: I/O operation failed
        UnsupportedFormatError: Archive format not supported
        InvalidArchiveError: With the integrity check on, a TAR entry whose
            content fails to decode (a resource limit or I/O failure while
            decoding raises its own typed error)
    """
    ...

class ArchiveError(Exception):
    """Base exception for all extraction errors."""

    ...

class PathTraversalError(ArchiveError):
    """
    Path traversal attempt detected.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class SymlinkEscapeError(ArchiveError):
    """
    Symlink points outside extraction directory.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class HardlinkEscapeError(ArchiveError):
    """
    Hardlink target outside extraction directory.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class ZipBombError(ArchiveError):
    """
    Potential zip bomb detected.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class InvalidPermissionsError(ArchiveError):
    """
    File permissions are invalid or unsafe.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class QuotaExceededError(ArchiveError):
    """
    Resource quota exceeded.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class ZipInconsistencyError(SecurityViolationError):
    """
    A ZIP archive's structure is read differently by different tools.

    Raised under the ``"enforce"`` ZIP consistency policy when local and central headers
    disagree, a name repeats, entries overlap, or the central directory or local headers
    hide records. Catching ``SecurityViolationError`` also catches it.

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class SecurityViolationError(ArchiveError):
    """
    Security policy violation.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Warning messages generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    warnings: list[str]

class UnsupportedFormatError(ArchiveError):
    """Archive format not supported."""

    ...

class UnknownFormatError(UnsupportedFormatError):
    """
    Archive format cannot be determined from the file path or magic bytes.

    This is a subclass of ``UnsupportedFormatError`` so existing callers that
    catch the parent continue to work, while callers that need to distinguish
    "we know the format but don't support it" from "we cannot identify the
    format at all" can catch this narrower type.
    """

    ...

class InvalidArchiveError(ArchiveError):
    """Archive is corrupted."""

    ...
