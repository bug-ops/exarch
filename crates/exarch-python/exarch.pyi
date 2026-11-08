"""
Memory-safe archive extraction library with security validation.

This module provides secure archive extraction, creation, listing, and verification
with built-in protection against path traversal, zip bombs, symlink attacks,
and other common vulnerabilities.

Entry names that are not valid UTF-8 are never replaced: paths in manifests,
reports, skips, verification issues and progress callbacks are decoded with
``os.fsdecode`` (surrogateescape on Unix), which is injective, so two distinct
entries never share a listed name. This differs from the CLI and the Node
binding, which show an escaped text form; use ``os.fsencode`` to get the raw
bytes back. The in-memory functions refuse such names instead.

The aliases ``AnyMemoryEntry``, ``AnyArchiveEntry``, ``AnyLinkTarget``,
``AnyExtractionWarning``, ``AnyCreationWarning``, ``AnyEntryDisposition`` and
``ProgressCallbackFn`` are
importable at runtime as typing objects.
"""

from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, Literal, Protocol, final

__version__: str

class _ArchiveFile(Protocol):
    """A binary file object: ``read(n)`` returns at most ``n`` bytes; ``seek``/``tell`` optional."""

    def read(self, size: int, /) -> bytes: ...

_ArchiveData = bytes | bytearray | _ArchiveFile

# Stub-only aliases: the native module does not export them at runtime.
_ArchiveType = Literal["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip", "SevenZ"]
_CreatableFormat = Literal["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip"]
_ManifestEntryType = Literal["File", "Directory", "Symlink", "Hardlink"]
_VerificationStatus = Literal["PASS", "FAIL", "WARNING"]
_CheckStatus = Literal["OK", "FAILED", "WARNING", "SKIPPED"]
_IntegrityStatus = Literal["OK", "FAILED", "INCOMPLETE", "SKIPPED"]
_UnverifiedReason = Literal["over_budget", "resource_limit", "solid_policy", "size_ceiling", "uncovered_block_crc", "not_decodable", "no_end_marker", "path_too_long", "descriptor_tail"]  # noqa: E501  # fmt: skip
_IssueSeverity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_IssueCategory = Literal["Path Traversal", "Symlink Escape", "Hardlink Escape", "Zip Bomb", "Invalid Permissions", "Quota Exceeded", "Security Policy", "Invalid Archive", "Suspicious Path", "Executable File", "Corrupt Data", "Integrity Incomplete", "Header Mismatch", "Duplicate Entry", "Overlapping Entries", "Hidden Entry", "Name Collision", "Archive Note"]  # noqa: E501  # fmt: skip
_ZipConsistency = Literal["enforce", "ignore"]
_Durability = Literal["synced", "unsynced"]
_ExistingFiles = Literal["skip", "overwrite", "refuse"]
_Staging = Literal["in_place", "atomic", "atomic_replace"]
_Restore = Literal["not_needed", "restored", "failed"]
_ProtectedPath = Literal["filesystem_root", "archive_ancestor", "working_directory"]
_IoKind = Literal[
    "NotFound",
    "PermissionDenied",
    "AlreadyExists",
    "NotADirectory",
    "IsADirectory",
    "DirectoryNotEmpty",
    "ReadOnlyFilesystem",
    "StorageFull",
    "QuotaExceeded",
    "FileTooLarge",
    "InvalidInput",
    "InvalidData",
    "InvalidFilename",
    "TimedOut",
    "Interrupted",
    "UnexpectedEof",
    "WriteZero",
    "Unsupported",
    "CrossesDevices",
    "TooManyLinks",
    "ResourceBusy",
    "BrokenPipe",
    "OutOfMemory",
    "WouldBlock",
    "Other",
]
_BackupIdentity = Literal["verified", "unverified"]
_ExtractionWarningKind = Literal["anti_items_skipped", "backup_cleanup_failed"]
_CreationWarningKind = Literal["zip_ratio_over_default_limit", "zip_ratio_check_failed", "directory_not_synced"]  # noqa: E501  # fmt: skip
_InvalidArchiveSubCode = Literal[
    "TAR_AMBIGUITY",
    "TAR_TRAILER",
    "LINK_TARGET",
    "DUPLICATE_ENTRY",
    "ENTRY_NAME",
    "DECLARED_SIZE",
    "INTEGRITY",
    "ZIP_READER",
    "TAR_READER",
    "SEVENZ_READER",
]
_QuotaSubCode = Literal[
    "FILE_COUNT",
    "TOTAL_SIZE",
    "FILE_SIZE",
    "INTEGER_OVERFLOW",
    "DECODER_MEMORY",
    "COMPRESSED_MEMBERS",
    "TREE_NODES",
    "SINK_CAPACITY",
    "SOLID_BLOCK_MEMORY",
    "HEADER_SIZE",
    "HEADER_ENTRY_COUNT",
]
_ZipBombSubCode = Literal["ENTRY", "SOLID_BLOCK", "SKIPPED_ENTRIES"]
_SecurityViolationSubCode = Literal["PATH_NAME", "PATH_DEPTH", "LINK_TARGET", "LINK_POLICY", "EXISTING_SYMLINK", "ENTRY_TYPE", "ROOT_ENTRY", "ENCRYPTED", "COMPRESSION_METHOD", "SOLID_ARCHIVE", "DECLARED_SIZE", "CONCURRENT_CHANGE", "TAR_METADATA", "TAR_TRAILER", "PLATFORM", "OUTPUT_CONFLICT", "SOURCE_PATH"]  # noqa: E501  # fmt: skip
_PartialWrites = Literal["kept", "rolled_back", "discarded"]
_PathModel = Literal["host", "portable"]
_MemoryEntryKind = Literal["file", "directory", "symlink", "hardlink"]
_DecodeReuse = Literal["off", "memory", "temp_file"]
_LinkState = Literal["recorded", "missing", "unread", "unreadable", "oversized"]
_DispositionKind = Literal["extract", "skip", "refuse"]
_SkipKind = Literal[
    "duplicate",
    "extension_not_allowed",
    "not_selected",
    "stripped_away",
    "excluded",
    "hidden",
    "over_max_file_size",
    "symlink_unsupported",
    "unreadable",
]
_ErrorCode = Literal[
    "PATH_TRAVERSAL",
    "SYMLINK_ESCAPE",
    "HARDLINK_ESCAPE",
    "ZIP_BOMB",
    "ZIP_INCONSISTENCY",
    "QUOTA_EXCEEDED",
    "SECURITY_VIOLATION",
    "INVALID_ARCHIVE",
    "IO_ERROR",
    "INVALID_PERMISSIONS",
    "SOURCE_NOT_FOUND",
    "SOURCE_NOT_ACCESSIBLE",
    "OUTPUT_EXISTS",
    "INVALID_COMPRESSION_LEVEL",
    "UNKNOWN_FORMAT",
    "INVALID_CONFIGURATION",
    "CANCELLED",
]
_ConfigSetting = Literal[
    "max_file_size",
    "max_total_size",
    "max_file_count",
    "max_path_depth",
    "max_compression_ratio",
    "max_solid_compression_ratio",
    "max_solid_block_memory",
    "max_tar_metadata_bytes",
    "max_decoder_memory",
    "compressed_member_allowance",
    "decompression_budget",
    "allowed_extension",
    "banned_path_component",
    "output_path",
    "source_paths",
    "strip_prefix",
    "creation_format",
    "atomic_extraction",
    "zip_output_writer",
    "max_bytes",
    "parallel_decode_memory",
    "exclude_pattern",
    "zip_consistency",
    "path_model",
    "archive_format",
    "decode_reuse",
    "decode_reuse_limit",
    "skip_kind",
    "durability",
    "existing_files",
    "staging",
    "entry_selection",
    "entry_include",
    "entry_exclude",
    "strip_components",
]
_PolicySetting = Literal["symlinks", "hardlinks", "solid_archives", "banned_components", "max_path_depth", "windows_reserved_names", "max_tar_metadata_bytes"]  # noqa: E501  # fmt: skip

@final
class SecurityConfig:
    """
    Security configuration for archive extraction.

    All security features default to deny (secure-by-default policy).

    Every limit (file size, total size, file count, path depth, compression
    ratio, solid block memory) is refused at assignment: a builder method or a
    property setter raises ``InvalidConfigurationError`` (a ``ValueError``) for
    zero, a negative or oversized integer, and for a ratio that is not a
    positive finite number; ``bool`` raises ``TypeError``. The exception's
    ``setting`` attribute names the refused setting (``"max_file_size"``,
    ``"max_compression_ratio"``, ...). A limit reads ``None`` when it is
    unbounded, as in ``permissive()`` presets.
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
        """Sets the maximum file size in bytes.

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute names the
        refused setting (``"max_file_size"``).
        """
        ...

    def with_max_total_size(self, size: int) -> SecurityConfig:
        """Sets the maximum total size in bytes.

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is
        ``"max_total_size"``.
        """
        ...

    def with_max_compression_ratio(self, ratio: float) -> SecurityConfig:
        """Sets the maximum compression ratio.

        Solid 7z blocks are exempt: each block is checked as a whole against the
        limit of ``with_max_solid_compression_ratio`` (default 1000).

        Raises ``ValueError`` for a ratio that is not a positive finite number;
        its ``setting`` attribute is ``"max_compression_ratio"``.
        """
        ...

    def with_max_file_count(self, count: int) -> SecurityConfig:
        """
        Sets the maximum file count.

        Every entry counts in every operation and format: files, directories,
        links and skipped entries.

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is
        ``"max_file_count"``.
        """
        ...

    def with_max_path_depth(self, depth: int) -> SecurityConfig:
        """Sets the maximum path depth.

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is
        ``"max_path_depth"``.
        """
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
        """
        Allows or denies solid 7z archives.

        Allowing keeps solid limits that are already set. ``allow=False`` drops
        them, so allowing again afterwards starts from the defaults (512 MiB per
        block, ratio 1000), not from a limit set earlier.
        """
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
            InvalidConfigurationError: If ``size`` is zero, negative or above 2**64 - 1
                (``setting == "parallel_decode_memory"``).
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
        Sets the maximum decoded size in bytes of a solid 7z block.

        The limit bounds decoded volume per block, not resident memory, and exists only
        while solid archives are allowed: call ``with_allow_solid_archives`` first. Raises
        ``ValueError`` if *size* is zero or solid archives are not allowed. Its ``setting``
        attribute is ``"max_solid_block_memory"``.
        """
        ...

    def with_allow_windows_reserved_names(self, allow: bool = True) -> SecurityConfig:
        """
        Allows or denies names Windows reserves (``CON``, ``NUL``, ...).

        Refused by default on every platform, because an archive extracted here
        may be unpacked on Windows later.
        """
        ...

    def with_max_tar_metadata_bytes(self, size: int) -> SecurityConfig:
        """
        Sets the most bytes of TAR header and metadata records (GNU long names, PAX
        headers, sparse blocks) read between two consecutive entries (default: 4 MiB).

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is ``"max_tar_metadata_bytes"``.
        """
        ...

    def with_max_decoder_memory(self, size: int) -> SecurityConfig:
        """
        Sets the most memory in bytes a decoder may hold while decoding a compressed
        TAR or a 7z block (default: 256 MiB).

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is ``"max_decoder_memory"``.
        """
        ...

    def with_compressed_member_allowance(self, count: int) -> SecurityConfig:
        """
        Sets the base number of gzip members or bzip2 streams a compressed TAR may hold;
        every 16 KiB of decoded output adds one more (default: 10,000).

        Raises ``InvalidConfigurationError`` for zero, a negative or oversized integer;
        its ``setting`` attribute is ``"compressed_member_allowance"``.
        """
        ...

    def with_max_solid_compression_ratio(self, ratio: float) -> SecurityConfig:
        """
        Sets the compression ratio limit of a whole solid 7z block (default: 1000).

        The limit exists only while solid archives are allowed: call
        ``with_allow_solid_archives`` first. Raises ``InvalidConfigurationError`` for a
        ratio that is not a positive finite number or while solid archives are not
        allowed; its ``setting`` attribute is ``"max_solid_compression_ratio"``.
        """
        ...

    def with_preserve_permissions(self, preserve: bool = True) -> SecurityConfig:
        """Sets whether to preserve permissions from archive."""
        ...

    def add_allowed_extension(self, ext: str) -> SecurityConfig:
        """Adds an allowed file extension.

        A leading dot is accepted and removed, and the value is lowercased.
        Raises ``ValueError`` for an empty value or one holding whitespace, a
        path separator or an inner dot (``tar.gz``).
        """
        ...

    def add_banned_component(self, component: str) -> SecurityConfig:
        """Adds a banned path component.

        Raises ``ValueError`` for an empty value or one holding a path
        separator, ``.`` or ``..``.
        """
        ...

    def add_include_pattern(self, pattern: str) -> SecurityConfig:
        """
        Adds an include pattern: only entries that match an include pattern (and
        no exclude pattern) are extracted. Patterns use the grammar of
        ``CreationConfig`` exclude patterns and match the normalized archive
        path before any stripping. An include pattern that matches nothing fails
        the extraction after the scan with ``InvalidConfigurationError``
        (``setting == "entry_include"``, the ``unmatched_patterns``); the files
        already written stay (or are rolled back under an atomic ``staging``).

        Order of operations: the name is validated, matched on its original
        path, stripped or flattened, and the new name is validated again. The
        selection applies alike to ``extract_archive*``, ``list_archive*``
        (see ``ArchiveManifest.dispositions``) and ``verify_archive*``.

        Raises:
            InvalidConfigurationError: a refused pattern
                (``setting == "entry_include"``).
        """
        ...

    def add_exclude_pattern(self, pattern: str) -> SecurityConfig:
        """
        Adds an exclude pattern: a matching entry is not extracted, whatever the
        include patterns say. A pattern that matches nothing is not an error.

        Raises:
            InvalidConfigurationError: a refused pattern
                (``setting == "entry_exclude"``).
        """
        ...

    def with_strip_components(self, count: int) -> SecurityConfig:
        """
        Drops ``count`` leading path components from every selected entry. An
        entry the strip consumes entirely is skipped (``"stripped_away"``).
        Replaces ``with_flatten``.

        Raises:
            InvalidConfigurationError: zero, a negative or non-integer value, or
                one above ``max_path_depth`` (``setting == "strip_components"``).
        """
        ...

    def with_flatten(self, flatten: bool = True) -> SecurityConfig:
        """
        Lands every regular file under the destination root by its final path
        component only. Directories are skipped; a symlink or hardlink entry is
        refused. Replaces ``with_strip_components``.
        """
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
    def max_file_size(self) -> int | None:
        """Maximum size for a single file in bytes (default: 50 MB); None if unbounded."""
        ...

    @max_file_size.setter
    def max_file_size(self, value: int) -> None: ...
    @property
    def max_total_size(self) -> int | None:
        """Maximum total size for all files in bytes (default: 500 MB); None if unbounded."""
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
    def max_file_count(self) -> int | None:
        """
        Maximum number of entries (default: 10,000); None if unbounded.

        Every entry counts in every operation and format: files, directories,
        links and skipped entries.
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
    def max_solid_block_memory(self) -> int | None:
        """
        Maximum decoded size in bytes of a solid 7z block (default: 512 MB once solid
        archives are allowed, ``None`` while they are not).
        """
        ...

    @max_solid_block_memory.setter
    def max_solid_block_memory(self, value: int) -> None: ...
    @property
    def max_solid_compression_ratio(self) -> float | None:
        """
        Compression ratio limit of a whole solid 7z block (default: 1000 once solid
        archives are allowed, ``None`` while they are not).
        """
        ...

    @max_solid_compression_ratio.setter
    def max_solid_compression_ratio(self, value: float) -> None: ...
    @property
    def allow_windows_reserved_names(self) -> bool:
        """Whether names Windows reserves are allowed (default: False)."""
        ...

    @property
    def max_tar_metadata_bytes(self) -> int:
        """Most bytes of TAR header and metadata records between two entries (default: 4 MiB)."""
        ...

    @max_tar_metadata_bytes.setter
    def max_tar_metadata_bytes(self, value: int) -> None: ...
    @property
    def max_decoder_memory(self) -> int:
        """Most memory in bytes a decoder may hold (default: 256 MiB)."""
        ...

    @max_decoder_memory.setter
    def max_decoder_memory(self, value: int) -> None: ...
    @property
    def compressed_member_allowance(self) -> int:
        """Base number of gzip members or bzip2 streams of a compressed TAR (default: 10,000)."""
        ...

    @compressed_member_allowance.setter
    def compressed_member_allowance(self, value: int) -> None: ...
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
    def allowed_extensions(self) -> list[str] | None:
        """The allowed file extensions, normalized, or ``None`` when every extension is allowed.

        Assigning raises ``InvalidConfigurationError`` (``setting ==
        "allowed_extension"``) for an empty list or an entry
        ``add_allowed_extension`` would refuse. Assigning ``None`` is the only
        way to clear the list.
        """
        ...

    @allowed_extensions.setter
    def allowed_extensions(self, value: list[str] | None) -> None: ...
    @property
    def banned_path_components(self) -> list[str]:
        """List of banned path components.

        Assigning raises ``ValueError`` for an entry ``add_banned_component``
        would refuse.
        """
        ...

    @banned_path_components.setter
    def banned_path_components(self, value: list[str]) -> None: ...
    @property
    def include_patterns(self) -> list[str]:
        """The include patterns, in the order added; empty means every entry is a candidate."""
        ...

    @include_patterns.setter
    def include_patterns(self, value: list[str]) -> None: ...
    @property
    def exclude_patterns(self) -> list[str]:
        """The exclude patterns, in the order added."""
        ...

    @exclude_patterns.setter
    def exclude_patterns(self, value: list[str]) -> None: ...
    @property
    def strip_components(self) -> int | None:
        """The number of leading components dropped, or ``None`` when no strip is set.

        Assigning ``None`` removes a strip (a flatten stays).
        """
        ...

    @strip_components.setter
    def strip_components(self, value: int | None) -> None: ...
    @property
    def flatten(self) -> bool:
        """Whether files land by their final component only.

        Assigning ``True`` replaces a strip; ``False`` removes a flatten.
        """
        ...

    @flatten.setter
    def flatten(self, value: bool) -> None: ...

@final
class ListOptions:
    """
    Options controlling listing behavior.

    Listing a 7z archive leaves link targets unread by default, so it decodes no
    entry data; ``with_stored_targets`` reads them.
    """

    def __init__(self) -> None:
        """Creates a new ListOptions with defaults (link targets unread)."""
        ...

    @staticmethod
    def default() -> ListOptions:
        """Creates a ListOptions with defaults."""
        ...

    def with_stored_targets(self, read: bool = True) -> ListOptions:
        """Sets whether link targets kept in entry data are read (decodes their blocks)."""
        ...

    @property
    def stored_targets(self) -> bool:
        """Whether link targets kept in entry data are read (default: False)."""
        ...

@final
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
            InvalidConfigurationError: ``budget`` is zero, negative or above 2**64 - 1
                (``setting == "decompression_budget"``).
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

@final
class ExtractionOptions:
    """
    Options controlling extraction behavior (non-security).

    Separate from SecurityConfig to keep security settings focused.
    These options control operational behavior such as how existing files are
    treated.
    """

    def __init__(self) -> None:
        """Creates a new ExtractionOptions with defaults."""
        ...

    @staticmethod
    def default() -> ExtractionOptions:
        """Creates an ExtractionOptions with defaults."""
        ...

    def with_existing_files(self, value: _ExistingFiles) -> ExtractionOptions:
        """
        Sets how an existing file at a landing path is treated.

        ``"skip"`` (default) keeps the existing file and counts the entry as a
        duplicate skip. ``"overwrite"`` replaces it where the entry kinds allow.
        ``"refuse"`` raises ``OutputExistsError`` (code ``OUTPUT_EXISTS``, with
        ``conflicts``) for any occupant and never overwrites. A kind conflict is
        refused under every value.

        Raises:
            InvalidConfigurationError: any other string
                (``setting == "existing_files"``).
        """
        ...

    def with_staging(self, value: _Staging) -> ExtractionOptions:
        """
        Sets where extracted files are written first.

        ``"in_place"`` (default) writes into the destination, which may already
        hold files. ``"atomic"`` extracts into a temporary directory next to the
        destination and renames it into place on success; a failure or
        cancellation removes it. A destination that holds content raises
        ``OutputExistsError`` before anything is extracted, one that is not a
        directory raises ``InvalidConfigurationError`` (``setting ==
        "output_path"``), and a symlinked destination is resolved first.
        ``"atomic_replace"`` is ``"atomic"`` and also swaps the staged tree over
        an existing destination directory, replacing it as a whole: the original
        is renamed aside only once extraction succeeded and restored if the swap
        fails (see ``OSError.restore``). A destination that is a filesystem root,
        the archive's directory or an ancestor of it, or the working directory
        raises ``InvalidConfigurationError`` (``setting == "output_path"``).

        The staging directory is private (``0700``) while the archive
        extracts. On Unix the published root then takes the mode of the
        destination it replaces (or fills), never setuid; with
        ``"atomic_replace"`` also its owner as far as the caller may, and with
        ``"atomic"`` never the uid and the group only when the caller owns the
        destination. On Windows the staging directory inherits the ACL of the
        destination's parent, and ``"atomic"`` onto an existing empty
        directory raises ``OutputExistsError``.

        The in-memory functions take no staging.

        Raises:
            InvalidConfigurationError: any other string (``setting == "staging"``).
        """
        ...

    def build(self) -> ExtractionOptions:
        """Finalizes the configuration."""
        ...

    @property
    def existing_files(self) -> _ExistingFiles:
        """How an existing file is treated (default: ``"skip"``)."""
        ...

    @existing_files.setter
    def existing_files(self, value: _ExistingFiles) -> None: ...
    @property
    def staging(self) -> _Staging:
        """Where files are written first (default: ``"in_place"``)."""
        ...

    @staging.setter
    def staging(self, value: _Staging) -> None: ...

@final
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
        """Sets the compression level (1-9).

        Raises ``InvalidCompressionLevelError`` for a level outside 1-9.
        """
        ...

    @property
    def compression_level(self) -> int:
        """The compression level, 1-9 (default: 6)."""
        ...

    @compression_level.setter
    def compression_level(self, value: int | None) -> None:
        """
        Sets the level; ``None`` resets it to 6.

        Raises ``InvalidCompressionLevelError`` outside 1-9.
        """
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
        r"""
        Sets exclude patterns, matched against the archive entry path.

        Patterns are globs: ``*`` and ``?`` match within one path component
        (``?`` is exactly one byte), ``[a-c]`` is a positive ASCII class, and
        ``**`` as a whole component spans directories (``src/**/*.rs``). A
        name without ``/`` (``build``, ``*.tmp``) matches any path component
        at any depth, and so its subtree; a pattern with a ``/`` anywhere,
        a trailing one included (``docs/build``, ``target/``), matches from
        the archive root and its subtree. ``\`` is a separator, not an escape.

        Raises ``InvalidConfigurationError`` (``setting == "exclude_pattern"``)
        for an empty pattern, ``.``, ``..``, an absolute path, a leading ``!``,
        ``{`` or ``}``, ``**`` glued to other characters (``a**b``), a negated,
        POSIX or non-ASCII class, an unterminated class, a class range outside
        ``0-9``/``a-z``/``A-Z``, a comma, or leading or trailing whitespace.
        """
        ...

    @property
    def preserve_permissions(self) -> bool: ...
    @preserve_permissions.setter
    def preserve_permissions(self, value: bool) -> None: ...
    @property
    def follow_symlinks(self) -> bool: ...
    @follow_symlinks.setter
    def follow_symlinks(self, value: bool) -> None: ...
    @property
    def include_hidden(self) -> bool: ...
    @include_hidden.setter
    def include_hidden(self, value: bool) -> None: ...
    @property
    def exclude_patterns(self) -> list[str]:
        """The exclude patterns as text; assigning parses them like ``with_exclude_patterns``."""
        ...

    @exclude_patterns.setter
    def exclude_patterns(self, value: list[str]) -> None: ...
    def with_max_file_size(self, size: int | None) -> CreationConfig:
        """Sets maximum file size in bytes, or None for no limit (default).

        Raises ValueError naming ``max_file_size`` when the size is zero.
        """
        ...

    @property
    def max_file_size(self) -> int | None:
        """Maximum size for a single file in bytes; ``None`` means no limit (default)."""
        ...

    @max_file_size.setter
    def max_file_size(self, value: int | None) -> None:
        """Sets the limit; ``None`` removes it.

        Raises ``ValueError`` naming ``max_file_size`` for zero.
        """
        ...

    def build(self) -> CreationConfig:
        """Finalizes the configuration."""
        ...

@final
class Skip:
    """One entry an operation left out."""

    @property
    def kind(self) -> _SkipKind | str:
        """Why the entry was skipped."""
        ...

    @property
    def path(self) -> str:
        """The entry's path as the operation names it."""
        ...

    @property
    def io_kind(self) -> _IoKind | str | None:
        """The stable kind of the I/O failure behind an "unreadable" skip."""
        ...

@final
class Skipped:
    """
    Everything an operation left out: exact counts per kind plus a bounded
    sample of the individual entries.
    """

    @property
    def total(self) -> int:
        """How many entries were skipped, over all kinds."""
        ...

    @property
    def counts(self) -> dict[_SkipKind, int]:
        """The exact count of each kind that occurred."""
        ...

    @property
    def sample(self) -> list[Skip]:
        """The first skipped entries (at most 64)."""
        ...

    def count(self, kind: _SkipKind) -> int:
        """The exact count of one kind; ValueError for an unknown kind."""
        ...

    def __len__(self) -> int: ...

class ExtractionWarning:
    """
    A condition of an extraction worth surfacing that is not a skipped entry.

    The concrete class tells which condition it is (see ``AnyExtractionWarning``)
    and carries its fields; ``str(warning)`` is ``message``.
    """

    @property
    def kind(self) -> _ExtractionWarningKind | str:
        """The condition: ``"anti_items_skipped"`` or ``"backup_cleanup_failed"``."""
        ...

    @property
    def message(self) -> str:
        """Human-readable description; host paths are redacted like an exception message."""
        ...

@final
class AntiItemsSkippedWarning(ExtractionWarning):
    """7z anti-items, which mark deletions in an update archive, were not applied."""

    @property
    def kind(self) -> Literal["anti_items_skipped"]: ...
    @property
    def count(self) -> int:
        """How many anti-items the archive holds."""
        ...

@final
class BackupCleanupFailedWarning(ExtractionWarning):
    """
    The backup of the original destination, kept for an atomic replacement,
    could not be removed and must be cleaned up manually.
    """

    @property
    def kind(self) -> Literal["backup_cleanup_failed"]: ...
    @property
    def path(self) -> str:
        """Where the backup remains, redacted like an exception message."""
        ...

    @property
    def identity(self) -> _BackupIdentity | str:
        """Whether the backup's identity was confirmed before its removal failed."""
        ...

    @property
    def io_kind(self) -> _IoKind | str:
        """The stable kind of the removal failure."""
        ...

    @property
    def reason(self) -> str:
        """The failure text, redacted like an I/O error message."""
        ...

AnyExtractionWarning = AntiItemsSkippedWarning | BackupCleanupFailedWarning

class CreationWarning:
    """
    A condition of a creation worth surfacing that is not a skipped entry.

    The concrete class tells which condition it is (see ``AnyCreationWarning``)
    and carries its fields; ``str(warning)`` is ``message``.
    """

    @property
    def kind(self) -> _CreationWarningKind | str:
        """The condition."""
        ...

    @property
    def message(self) -> str:
        """Human-readable description."""
        ...

@final
class ZipRatioOverDefaultLimitWarning(CreationWarning):
    """
    Default extraction would refuse entries of the finished ZIP archive as a zip
    bomb, because their compression ratio is over the default limit.
    """

    @property
    def kind(self) -> Literal["zip_ratio_over_default_limit"]: ...
    @property
    def entries(self) -> int:
        """How many entries are over the limit."""
        ...

    @property
    def limit(self) -> float:
        """The default extraction ratio limit."""
        ...

    @property
    def needed_ratio(self) -> float:
        """The smallest ratio limit that admits every entry."""
        ...

@final
class ZipRatioCheckFailedWarning(CreationWarning):
    """
    The finished ZIP archive could not be read back to check its entries against
    the default extraction ratio limit.
    """

    @property
    def kind(self) -> Literal["zip_ratio_check_failed"]: ...
    @property
    def reason(self) -> str:
        """Why the archive could not be read back."""
        ...

@final
class DirectoryNotSyncedWarning(CreationWarning):
    """
    The archive was published, but the directory that holds it could not be
    synced, so the directory entry may not survive a crash.
    """

    @property
    def kind(self) -> Literal["directory_not_synced"]: ...
    @property
    def io_kind(self) -> _IoKind | str:
        """The stable kind of the failure."""
        ...

AnyCreationWarning = (
    ZipRatioOverDefaultLimitWarning | ZipRatioCheckFailedWarning | DirectoryNotSyncedWarning
)

@final
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
        """Number of entries skipped, over all kinds."""
        ...

    @property
    def skipped(self) -> Skipped:
        """The skipped entries by kind."""
        ...

    @property
    def warnings(self) -> list[AnyExtractionWarning]:
        """The typed warnings of the extraction."""
        ...

    def total_items(self) -> int:
        """Returns total number of items processed."""
        ...

    def has_warnings(self) -> bool:
        """Returns whether any warnings were generated."""
        ...

@final
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
        """Number of entries skipped, over all kinds (excluded, hidden, oversized, ...)."""
        ...

    @property
    def skipped(self) -> Skipped:
        """The skipped entries by kind."""
        ...

    @property
    def warnings(self) -> list[AnyCreationWarning]:
        """The typed warnings of the creation."""
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

class LinkTarget:
    """
    What listing learned of a link's target; narrow with ``isinstance`` or on
    ``state``. A 7z symlink is an ``UnreadLinkTarget``: listing does not decode
    7z entry data. A state this binding has no class for is a bare
    ``LinkTarget`` whose ``state`` is ``"unknown"``.
    """

    @property
    def state(self) -> str: ...

@final
class RecordedLinkTarget(LinkTarget):
    """A target the archive records."""

    @property
    def state(self) -> Literal["recorded"]: ...
    @property
    def path(self) -> str:
        """The target as the archive spells it."""
        ...

@final
class MissingLinkTarget(LinkTarget):
    """A link whose archive entry carries no target."""

    @property
    def state(self) -> Literal["missing"]: ...

@final
class UnreadLinkTarget(LinkTarget):
    """A target listing did not read."""

    @property
    def state(self) -> Literal["unread"]: ...

@final
class UnreadableLinkTarget(LinkTarget):
    """A target that could not be read."""

    @property
    def state(self) -> Literal["unreadable"]: ...

@final
class OversizedLinkTarget(LinkTarget):
    """A target too long to keep."""

    @property
    def state(self) -> Literal["oversized"]: ...
    @property
    def bytes(self) -> int:
        """The length of the target in bytes."""
        ...

AnyLinkTarget = (
    RecordedLinkTarget
    | MissingLinkTarget
    | UnreadLinkTarget
    | UnreadableLinkTarget
    | OversizedLinkTarget
)

class ArchiveEntry:
    """
    Single entry in archive manifest.

    The concrete class tells the kind; only ``ArchiveFile`` has a ``size``, and
    the link kinds have a ``target``.
    """

    @property
    def path(self) -> str:
        """
        Entry path. A name that is not valid UTF-8 is decoded with
        ``os.fsdecode`` (lossless on Unix), never replaced, so two entries never
        share a listed name.
        """
        ...

    @property
    def entry_type(self) -> _ManifestEntryType | str:
        """Entry type."""
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
    def modified(self) -> float | None:
        """Modification time in seconds since the Unix epoch, if the archive records one."""
        ...

    def compression_ratio(self) -> float | None:
        """
        Returns the compression ratio if the entry owns its compressed data.

        None for entries of a solid block, whose ratio is checked per block.
        """
        ...

@final
class ArchiveFile(ArchiveEntry):
    """A regular file."""

    @property
    def entry_type(self) -> Literal["File"]: ...
    @property
    def size(self) -> int:
        """Uncompressed size in bytes."""
        ...

@final
class ArchiveDirectory(ArchiveEntry):
    """A directory."""

    @property
    def entry_type(self) -> Literal["Directory"]: ...

@final
class ArchiveSymlink(ArchiveEntry):
    """A symbolic link."""

    @property
    def entry_type(self) -> Literal["Symlink"]: ...
    @property
    def target(self) -> AnyLinkTarget: ...

@final
class ArchiveHardlink(ArchiveEntry):
    """A hard link."""

    @property
    def entry_type(self) -> Literal["Hardlink"]: ...
    @property
    def target(self) -> AnyLinkTarget: ...

AnyArchiveEntry = ArchiveFile | ArchiveDirectory | ArchiveSymlink | ArchiveHardlink

@final
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
    def entries(self) -> list[AnyArchiveEntry]:
        """List of archive entries."""
        ...

    @property
    def format(self) -> _ArchiveType | str:
        """Archive format."""
        ...

    @property
    def dispositions(self) -> list[AnyEntryDisposition]:
        """
        What extraction would do with each entry: where it lands, why it is left
        out, or that the validation refuses it (``action == "refuse"``). Computed
        when the archive was listed, under that call's ``SecurityConfig``
        (selection, limits and policies).
        """
        ...

class EntryDisposition:
    """What extraction does with one listed entry (see ``AnyEntryDisposition``)."""

    action: ClassVar[_DispositionKind | str]

    @property
    def path(self) -> str:
        """The entry's path in the archive."""
        ...

@final
class ExtractDisposition(EntryDisposition):
    """An entry that extraction writes."""

    action: ClassVar[Literal["extract"]]

    @property
    def landing(self) -> str:
        """Where it lands, relative to the destination, after any strip or flatten."""
        ...

@final
class SkipDisposition(EntryDisposition):
    """An entry that is validated but not extracted."""

    action: ClassVar[Literal["skip"]]

    @property
    def kind(self) -> _SkipKind | str:
        """Why it is left out."""
        ...

@final
class RefuseDisposition(EntryDisposition):
    """An entry that is refused by validation or policy, or cannot be placed."""

    action: ClassVar[Literal["refuse"]]

AnyEntryDisposition = ExtractDisposition | SkipDisposition | RefuseDisposition

@final
class VerificationIssue:
    """Verification issue."""

    @property
    def severity(self) -> _IssueSeverity | str:
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
    def category(self) -> _IssueCategory | str:
        """Issue category."""
        ...

    @property
    def code(self) -> _ErrorCode | str | None:
        """
        The error code of a refusal, the same an exception of that refusal
        carries; None for a heuristic finding.
        """
        ...

    @property
    def sub_code(
        self,
    ) -> (
        _InvalidArchiveSubCode | _SecurityViolationSubCode | _QuotaSubCode | _ZipBombSubCode | None
    ):
        """The sub-code of the refusal (a security, invalid-archive, quota or zip bomb code)."""
        ...

    @property
    def relaxable_by(self) -> _PolicySetting | str | None:
        """The policy setting that would admit the refused entry, if one does."""
        ...

    @property
    def setting(self) -> _ConfigSetting | str | None:
        """The configuration setting the refusal concerns, if any."""
        ...

    @property
    def io_kind(self) -> _IoKind | str | None:
        """The stable kind of the I/O failure of an ``IO_ERROR`` refusal, else None."""
        ...

    @property
    def mode(self) -> int | None:
        """The permission bits of an invalid-permissions refusal or an
        executable-file finding; None otherwise.
        """
        ...

@final
class UnverifiedEntry:
    """One entry the integrity check could not verify."""

    @property
    def path(self) -> str:
        """Entry path inside the archive."""
        ...

    @property
    def reason(self) -> _UnverifiedReason | str:
        """Why the entry was not verified."""
        ...

@final
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

@final
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
    def status(self) -> _VerificationStatus | str:
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
    def suspicious_entries(self) -> int:
        """Entries flagged as suspicious."""
        ...

    @property
    def total_size(self) -> int:
        """Total uncompressed size."""
        ...

    @property
    def format(self) -> _ArchiveType | str:
        """Archive format."""
        ...

    @property
    def integrity_status(self) -> _IntegrityStatus | str:
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
    def security_status(self) -> _CheckStatus | str:
        """Security check result."""
        ...

    def is_safe(self) -> bool:
        """Returns true if the archive is safe (no Medium-or-higher severity issues)."""
        ...

    def has_critical_issues(self) -> bool:
        """Returns true if there are any critical severity issues."""
        ...

ProgressCallbackFn = Callable[[str, int | None, int, int], None]
"""
Progress callback: (path, total, current, bytes_written) -> None.

``current`` counts from 1. ``total`` is None when the number of entries is not
known up front, as when a TAR stream is read.
"""

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
        ``warnings`` attributes attached, plus ``writes`` (``"kept"``). With
        ``staging="atomic"`` the destination is rolled back instead: the exception
        then carries ``writes == "rolled_back"`` and none of the counter
        attributes. Detect files left on disk via
        ``getattr(e, "writes", None) == "kept"``; ``hasattr(e, "writes")``
        is also true after a rollback. The ``*_to_memory`` functions write
        nothing to disk: their failures carry ``writes == "discarded"`` and none
        of the counter attributes. A symlink entry over an existing symlink
        with a different target, with overwrite enabled
        (``existing_files == "overwrite"``), raises the builtin ``OSError`` (``ELOOP``), not
        ``SymlinkEscapeError``. See
        ``extract_archive_with_progress`` below: a raising ``progress`` callback
        carries ``writes`` and the counters of what was written, distinguished by
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
        The GIL is released during extraction whether or not a callback is
        provided; the callback takes it back for each call.

        Progress callback limitations:

        - The ``bytes_written`` argument reflects ``on_bytes_written`` events
          from the core library. Extraction does not emit byte-level progress,
          only entry-level events, so ``bytes_written`` will always be 0 during
          extraction.
        - For TAR-family formats (tar, tar.gz, tar.bz2, tar.xz, tar.zst) the
          ``total`` argument is ``None`` because the entry count is unknown
          until the stream is fully read.

        When extraction fails after some files have already been written to disk,
        the specific exception (e.g. ``SymlinkEscapeError``) is raised with
        ``files_extracted``, ``bytes_written``, ``files_skipped``, and
        ``warnings`` attributes attached.

        If ``progress`` itself raises (``KeyboardInterrupt`` included),
        extraction is cancelled: it stops before the next entry, and
        ``progress`` is not called again. What was written stays on disk (or is
        rolled back under an atomic ``staging``):

        - ``progress``'s own exception is what propagates (unchanged — the same
          type, message, and traceback), with ``writes`` and, while the files
          remain on disk, ``files_extracted``, ``bytes_written``,
          ``files_skipped``, ``skipped`` and ``warnings`` attributes attached,
          plus a ``progress_callback_error = True`` marker attribute. Check
          ``progress_callback_error`` before treating the presence of
          ``files_extracted`` as a partial-extraction signal — see the note on
          ``extract_archive`` above.
        - If extraction fails for its own reason first, the extraction error
          takes priority (a
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
    format: _CreatableFormat | None = None,
    overwrite: bool = True,
    durability: _Durability | None = None,
) -> CreationReport:
    """
    Create an archive from source files and directories.

    The archive is written to a temporary file next to ``output_path`` (whose
    directory must be writable) and renamed into place when complete, so a
    failed creation leaves ``output_path`` as it was. The output and its
    temporary file are never archived, even inside a source directory.

    Args:
        output_path: Path to output archive file (str or pathlib.Path)
        sources: List of source files/directories to include (str or pathlib.Path)
        config: Optional CreationConfig (uses defaults if None)
        format: The format to write whatever the extension is (for example
            "Zip" for a ``.whl``); None detects it from the extension
        overwrite: Replace an existing regular file or symlink, keeping its
            permission bits (default); False refuses any existing output
        durability: "synced" (the default, also for ``None``) flushes the archive and its directory
            entry before returning. "unsynced" skips both: faster, but after a
            crash or power loss a replaced output can be empty or truncated and
            a new output can be empty, and write-back errors (network
            filesystems, quotas, delayed allocation) are not reported

    Returns:
        CreationReport with creation statistics

    Raises:
        OutputExistsError: ``overwrite`` is False and ``output_path`` exists
        InvalidConfigurationError: ``output_path`` is a directory, FIFO or device
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
    format: _CreatableFormat | None = None,
    overwrite: bool = True,
    durability: _Durability | None = None,
) -> CreationReport:
    """
    Create an archive with progress reporting.

    ``format``, ``overwrite`` and ``durability`` are as in create_archive.

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
        If ``progress`` raises (``KeyboardInterrupt`` included), creation is
        cancelled at the next entry: the staged archive is discarded, a previous
        archive at ``output_path`` stays untouched and no temporary file is
        left. ``progress`` is not called again, and its own exception propagates
        unchanged with a ``progress_callback_error = True`` marker attribute.
        If creation fails for its own reason first, that error takes priority (a
        raising ``progress`` can never mask a security error such as
        ``SymlinkEscapeError``) and ``progress``'s exception is attached as
        ``__cause__``.

    Example:
        >>> def progress(path: str, total: int, current: int, bytes: int):
        ...     print(f"{current}/{total}: {path} ({bytes} bytes)")
        >>> report = create_archive_with_progress("output.tar.gz", ["src/"], None, progress)
    """
    ...

def list_archive(
    archive_path: str | Path,
    config: SecurityConfig | None = None,
    options: ListOptions | None = None,
) -> ArchiveManifest:
    """
    List archive contents without extracting.

    Args:
        archive_path: Path to archive file (str or pathlib.Path)
        config: Optional SecurityConfig (uses secure defaults if None)
        options: Optional ListOptions; ``ListOptions().with_stored_targets()``
            reads the 7z link targets that listing leaves unread by default

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

def list_archive_bytes(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    format: _ArchiveType | None = None,
    options: ListOptions | None = None,
) -> ArchiveManifest:
    """
    List the contents of an archive held in memory, without extracting.

    Args:
        data: The archive bytes, or a binary file object. A file object is read from
            its current position; if it is seekable any format works, otherwise only
            the TAR family. An exception it raises propagates unchanged.
        config: Optional SecurityConfig (uses secure defaults if None)
        format: The archive format; detected from the leading bytes if None
        options: Optional ListOptions, as in list_archive

    Returns:
        ArchiveManifest with entry metadata

    Raises:
        ValueError: Unknown format
        UnknownFormatError: The format cannot be detected from the bytes
        InvalidArchiveError: Archive is corrupted
    """
    ...

def verify_archive_bytes(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    options: VerificationOptions | None = None,
    format: _ArchiveType | None = None,
) -> VerificationReport:
    """
    Verify the security of an archive held in memory.

    Args:
        data: The archive bytes, or a binary file object. A file object is read from
            its current position; if it is seekable any format works, otherwise only
            the TAR family. An exception it raises propagates unchanged.
        config: Optional SecurityConfig (uses secure defaults if None)
        options: Optional VerificationOptions
        format: The archive format; detected from the leading bytes if None

    Returns:
        VerificationReport with validation results

    Raises:
        ValueError: Unknown format
        UnknownFormatError: The format cannot be detected from the bytes
        InvalidArchiveError: Archive is corrupted
    """
    ...

class MemoryEntry:
    """
    An entry extracted into memory.

    The concrete class tells what the entry holds; narrow with ``isinstance``
    or on ``kind``. Each class carries only the attributes of its kind. A kind
    this binding has no class for is a bare ``MemoryEntry`` with its ``kind``.
    """

    @property
    def path(self) -> str:
        """Entry path, relative, as delivered by extraction."""
        ...

    @property
    def kind(self) -> _MemoryEntryKind | str:
        """What the entry holds."""
        ...

@final
class MemoryFile(MemoryEntry):
    """A regular file."""

    @property
    def kind(self) -> Literal["file"]: ...
    @property
    def data(self) -> bytes:
        """The file's bytes."""
        ...

    @property
    def mode(self) -> int | None:
        """Permission bits after setuid and setgid were stripped, if the archive carries a mode."""
        ...

@final
class MemoryDirectory(MemoryEntry):
    """A directory the archive names explicitly."""

    @property
    def kind(self) -> Literal["directory"]: ...

@final
class MemorySymlink(MemoryEntry):
    """A symbolic link, stored as data."""

    @property
    def kind(self) -> Literal["symlink"]: ...
    @property
    def target(self) -> str:
        """The target as the archive spells it, relative to the link."""
        ...

@final
class MemoryHardlink(MemoryEntry):
    """A hard link to an already delivered entry; only from extract_archive_to_callback."""

    @property
    def kind(self) -> Literal["hardlink"]: ...
    @property
    def target(self) -> str:
        """The root-relative resolved path of an already delivered file or earlier hardlink."""
        ...

AnyMemoryEntry = MemoryFile | MemoryDirectory | MemorySymlink | MemoryHardlink

@final
class SinkOptions:
    """
    What the in-memory and callback extraction functions honour of the options
    of path-based extraction.

    Atomic extraction renames a directory, which an in-memory extraction does
    not have, so only the existing-files policy and the ZIP decode reuse remain.

    Args:
        existing_files: ``"skip"`` (default) skips an entry whose path an
            earlier entry already holds and counts a duplicate; ``"overwrite"``
            delivers it again; ``"refuse"`` raises ``OutputExistsError``.
        decode_reuse: Where a ZIP extraction keeps the output of its structural
            check so deflate entries are decoded once instead of twice:
            ``"off"`` (default), ``"memory"`` or ``"temp_file"``.
            ``"temp_file"`` writes the plaintext of the archive to the
            temporary directory until the extraction ends.
        decode_reuse_limit: The most bytes kept, at most 256 MiB (default
            32 MiB). Only with ``"memory"`` or ``"temp_file"``.

    Raises:
        ValueError: Unknown ``decode_reuse``, a non-positive limit, or a limit
            with ``"off"``.
    """

    def __new__(
        cls,
        existing_files: _ExistingFiles = "skip",
        decode_reuse: _DecodeReuse = "off",
        decode_reuse_limit: int | None = None,
    ) -> SinkOptions: ...
    @property
    def existing_files(self) -> _ExistingFiles: ...
    @property
    def decode_reuse(self) -> _DecodeReuse: ...
    @property
    def decode_reuse_limit(self) -> int | None:
        """The limit in bytes; None for ``"off"``."""
        ...

@final
class MemoryExtraction:
    """The result of extract_archive_to_memory."""

    @property
    def report(self) -> ExtractionReport:
        """Extraction statistics."""
        ...

    @property
    def entries(self) -> list[AnyMemoryEntry]:
        """The extracted entries in path order."""
        ...

def extract_archive_to_memory(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    options: SinkOptions | None = None,
    max_bytes: int | None = None,
    path_model: _PathModel | None = None,
    format: _ArchiveType | None = None,
) -> MemoryExtraction:
    """
    Extract an archive held in memory into memory.

    The archive passes the same validation as extract_archive; nothing is
    written to disk.

    Args:
        data: The archive bytes, or a binary file object. A file object is read from
            its current position; if it is seekable any format works, otherwise only
            the TAR family. An exception it raises propagates unchanged.
        config: Optional SecurityConfig (uses secure defaults if None)
        options: Optional SinkOptions
        max_bytes: The most bytes to keep: payload (file data, hardlink copies
            and symlink targets) plus path bytes plus 256 per entry; defaults
            to the config's max_total_size
        path_model: "host" (default) validates names against this platform's
            rules, "portable" against the strictest rules of every platform
        format: The archive format; detected from the leading bytes if None

    Returns:
        MemoryExtraction with the report and the extracted entries

    Raises:
        ValueError: Unknown format or path_model, or max_bytes of zero
        QuotaExceededError: A quota, or max_bytes, was exceeded
        UnknownFormatError: The format cannot be detected from the bytes
    """
    ...

def extract_archive_to_callback(
    data: _ArchiveData,
    on_entry: Callable[[AnyMemoryEntry], object],
    config: SecurityConfig | None = None,
    options: SinkOptions | None = None,
    path_model: _PathModel | None = None,
    format: _ArchiveType | None = None,
) -> ExtractionReport:
    """
    Extract an archive into a callback, one verified entry at a time.

    Nothing is written to disk and nothing is kept. on_entry receives a
    MemoryEntry per entry in extraction order; its return value is ignored.
    A file arrives whole, after its declared size was verified, so memory use
    is one file, bounded by the config's max_file_size. The GIL is released
    during I/O and taken once per entry.

    Entries are provisional: each is delivered as soon as it is verified, so a
    later failure refuses the archive after earlier entries were already
    delivered. Treat the results as final only once the call returned. The
    gzip CRC of a .tar.gz is verified after the end-of-archive marker, so a
    corrupt compressed stream refuses the archive only after its entries were
    delivered.

    A "symlink" entry's target is spelled as the archive stores it, relative
    to the link. A "hardlink" entry is delivered by reference after every other
    entry: its target is the root-relative resolved path of an entry already
    delivered, a file or an earlier hardlink (a chain is delivered link by
    link). With existing_files="overwrite" one path can be delivered more than
    once and a hardlink refers to the latest delivery. Implicit parent
    directories are not delivered.

    Args:
        data: The archive bytes, or a binary file object (see
            extract_archive_to_memory)
        on_entry: Called with each MemoryEntry
        config: Optional SecurityConfig (uses secure defaults if None)
        options: Optional SinkOptions
        path_model: "host" (default) or "portable"
        format: The archive format; detected from the leading bytes if None

    Raises:
        TypeError: on_entry is not callable
        ValueError: Unknown format or path_model
        Whatever on_entry raises, unchanged: the first exception stops the
        extraction and is re-raised as is, with no marker added.
    """
    ...

def extract_archive_to_memory_with_progress(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    progress: ProgressCallbackFn | None = None,
    options: SinkOptions | None = None,
    max_bytes: int | None = None,
    path_model: _PathModel | None = None,
    format: _ArchiveType | None = None,
) -> MemoryExtraction:
    """
    Extract an archive held in memory into memory, reporting progress.

    Same as extract_archive_to_memory, plus a callback invoked once per entry
    with (path, total, current, bytes_written). The GIL is released during
    extraction and taken once per callback.

    Raises:
        Whatever progress itself raises: it cancels the extraction before the
        next entry, the collected entries are discarded and the exception
        carries writes == "discarded" (no counters) and
        progress_callback_error = True. If extraction failed for its own reason
        first, the core error is raised with the callback's exception chained
        as __cause__.
    """
    ...

def list_archive_bytes_with_progress(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    progress: ProgressCallbackFn | None = None,
    format: _ArchiveType | None = None,
    options: ListOptions | None = None,
) -> ArchiveManifest:
    """
    List the contents of an archive held in memory, reporting progress.

    Same as list_archive_bytes, plus a callback invoked once per entry with
    (path, total, current, bytes_written); total is None for TAR and
    bytes_written is always 0.

    Raises:
        Whatever progress itself raises: it cancels the listing before the next
        entry and the exception carries progress_callback_error = True. If
        listing failed for its own reason first, the core error is raised with
        the callback's exception chained as __cause__.
    """
    ...

def verify_archive_bytes_with_progress(
    data: _ArchiveData,
    config: SecurityConfig | None = None,
    progress: ProgressCallbackFn | None = None,
    options: VerificationOptions | None = None,
    format: _ArchiveType | None = None,
) -> VerificationReport:
    """
    Verify the security of an archive held in memory, reporting progress.

    Same as verify_archive_bytes, plus a callback invoked once per entry with
    (path, total, current, bytes_written); total is None for TAR and
    bytes_written is always 0.

    Raises:
        Whatever progress itself raises: it cancels the verification before the
        next entry and the exception carries progress_callback_error = True. If
        verification errored for its own reason first, the core error is raised
        with the callback's exception chained as __cause__.
    """
    ...

@final
class CreatedArchive:
    """The result of create_archive_to_bytes."""

    @property
    def data(self) -> bytes:
        """The archive bytes."""
        ...

    @property
    def report(self) -> CreationReport:
        """Creation statistics."""
        ...

def create_archive_to_bytes(
    sources: list[str | Path],
    format: _CreatableFormat,
    config: CreationConfig | None = None,
) -> CreatedArchive:
    """
    Create an archive from source files and directories into memory.

    The whole archive is held in memory (about 2-3x its size at the peak) with
    no size cap; use create_archive for large archives. Sources must be regular
    files and directories; FIFOs and device files are not supported.

    Args:
        sources: List of source files/directories to include (str or pathlib.Path)
        format: The archive format; "SevenZ" cannot be created
        config: Optional CreationConfig (uses defaults if None)

    Returns:
        CreatedArchive with the archive bytes and the report

    Raises:
        ValueError: Unknown format, invalid sources, or "SevenZ"
        IOError: A source cannot be read
    """
    ...

class _IOErrorAttributes(Protocol):
    """
    Attributes exarch sets on the builtin ``OSError`` it raises for an I/O
    failure (``code == "IO_ERROR"``).

    These errors are plain builtin ``OSError`` subclasses (``PermissionError``,
    ``FileNotFoundError``, ... and a bare ``OSError`` for kinds Python has no
    class for; an out-of-memory failure included), not ``ArchiveError``
    subclasses, so type checkers see only ``OSError``. Read the attributes with
    ``getattr``; ``code``, ``io_kind``, ``restore``, ``backup_path``,
    ``leftover_path`` and ``filename`` are always set (``None`` when they do not
    apply), ``writes`` only after an extraction recorded progress.

    Attributes:
        code: Always ``"IO_ERROR"``.
        io_kind: The stable kind of the failure, the same token as
            ``Skip.io_kind``.
        restore: On the error of a failed ``"atomic_replace"`` swap:
            ``"not_needed"`` (the original destination was never moved),
            ``"restored"`` (moved aside and back) or ``"failed"`` (it could not
            be moved back and remains at ``backup_path``).
        backup_path: With ``restore == "failed"``, where the original destination
            remains, redacted like an exception message.
        leftover_path: Where a staging directory or reservation file the
            failure left behind remains, redacted like an exception message.
        filename: On the error of a creation that failed after reserving its
            output, the empty reservation file left at that path (redacted).
        writes: As on ``ArchiveError``, when extraction failed after recording
            progress.
    """

    code: Literal["IO_ERROR"]
    io_kind: _IoKind
    restore: _Restore | None
    backup_path: str | None
    leftover_path: str | None
    filename: str | None
    writes: _PartialWrites

class ArchiveError(Exception):
    """
    Base exception for all extraction errors.

    Attributes:
        code: The stable error code, the same on every exarch exception,
            including the builtin ``OSError`` subclasses raised for I/O
            failures.
        leftover_path: Where a staging directory the failure left behind
            remains, redacted like an exception message; ``None`` when nothing
            was left.
        writes: Set only when extraction failed after recording progress:
            ``"kept"`` if the written files remain on disk, ``"rolled_back"``
            if atomic extraction discarded them, ``"discarded"`` if an
            in-memory extraction dropped the entries it had collected.
    """

    # Set on each instance when the error is raised; the class has no default,
    # so `ArchiveError.code` itself raises AttributeError.
    code: _ErrorCode
    leftover_path: str | None
    writes: _PartialWrites

class OutputExistsError(ArchiveError, FileExistsError):
    """
    The output path already exists, or an extraction refused to touch an
    existing path (``code == "OUTPUT_EXISTS"``).

    ``errno`` is ``EEXIST`` and ``filename`` the output or destination path,
    redacted like an exception message, as ``open()`` fills them.

    Attributes:
        conflicts: The archive-relative paths an extraction with
            ``existing_files == "refuse"`` found occupied; ``None`` for a
            creation output that exists.
    """

    conflicts: list[str] | None

class SourceNotFoundError(ArchiveError, FileNotFoundError):
    """
    A source path or archive does not exist (``code == "SOURCE_NOT_FOUND"``).

    ``errno`` is ``ENOENT``, ``strerror`` its text and ``filename`` the path,
    redacted like an exception message, as ``open()`` fills them.
    """

    ...

class SourceNotAccessibleError(ArchiveError, OSError):
    """
    A source path exists but cannot be read (``code == "SOURCE_NOT_ACCESSIBLE"``).

    ``errno``, ``strerror`` and ``filename`` carry the OS error when there is one.
    """

    ...

class InvalidConfigurationError(ArchiveError, ValueError):
    """
    A setting or argument was refused (``code == "INVALID_CONFIGURATION"``).

    Attributes:
        setting: The refused setting, or ``None`` when the refusal names none.
        unmatched_patterns: With ``setting == "entry_include"`` after an extraction, the
            include patterns that matched no entry; ``None`` otherwise.
        protected_path: With ``setting == "output_path"`` when an
            ``"atomic_replace"`` destination was refused, what it is:
            ``"filesystem_root"``, ``"archive_ancestor"`` (the archive's own
            directory or an ancestor of it) or ``"working_directory"``;
            ``None`` otherwise.
        collision: With ``setting == "source_paths"`` when two creation sources
            map to one entry name, the colliding pair; ``None`` otherwise.
    """

    setting: _ConfigSetting | None
    unmatched_patterns: list[str] | None
    protected_path: _ProtectedPath | None
    collision: NameCollision | None

@final
class NameCollision:
    """Two creation sources that map to one entry name."""

    @property
    def name(self) -> str:
        """The entry name both sources map to."""
        ...

    @property
    def first(self) -> str:
        """The first source, redacted like an exception message."""
        ...

    @property
    def second(self) -> str:
        """The second source, redacted like an exception message."""
        ...

class InvalidCompressionLevelError(ArchiveError, ValueError):
    """A compression level is out of range (``code == "INVALID_COMPRESSION_LEVEL"``)."""

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
        warnings: Typed warnings generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]

class SymlinkEscapeError(ArchiveError):
    """
    Symlink points outside extraction directory.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]

class HardlinkEscapeError(ArchiveError):
    """
    Hardlink target outside extraction directory.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]

class ZipBombError(ArchiveError):
    """
    Potential zip bomb detected.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
        sub_code: What the ratio was measured over: one entry, a solid block or the skipped entries.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    sub_code: _ZipBombSubCode
    warnings: list[AnyExtractionWarning]

class InvalidPermissionsError(ArchiveError):
    """
    File permissions are invalid or unsafe.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]

class QuotaExceededError(ArchiveError):
    """
    Resource quota exceeded.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
        sub_code: Which quota was exceeded.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    sub_code: _QuotaSubCode
    warnings: list[AnyExtractionWarning]

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
        warnings: Typed warnings generated before the error.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]

class SecurityViolationError(ArchiveError):
    """
    Security policy violation.

    When raised during ``extract_archive``, the following attributes are
    available if some files were already written before the error occurred:

    Attributes:
        files_extracted: Number of files successfully extracted before the error.
        bytes_written: Total bytes written to disk before the error.
        files_skipped: Number of entries skipped due to security checks before the error.
        warnings: Typed warnings generated before the error.
        relaxable_by: The ``SecurityConfig`` setting whose current value refused
            the entry, or ``None`` when no setting relaxes this refusal. Changing
            that setting removes this refusal only; the entry can still fail a
            later check. ``"windows_reserved_names"`` and
            ``"max_tar_metadata_bytes"`` have no setter in this binding (Rust
            API only).
        sub_code: The family of the refusal, set on every violation raised by the
            core (``"PATH_NAME"``, ``"LINK_TARGET"``, ``"ENCRYPTED"``,
            ``"TAR_TRAILER"``, ...); ``None`` only on the class itself.
    """

    files_extracted: int
    bytes_written: int
    files_skipped: int
    skipped: Skipped
    warnings: list[AnyExtractionWarning]
    relaxable_by: _PolicySetting | None
    sub_code: _SecurityViolationSubCode | None

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
    """
    Archive is corrupted.

    Attributes:
        sub_code: ``"TAR_AMBIGUITY"`` when a TAR header is read differently by
            different tools, ``"TAR_TRAILER"`` when the stream after the TAR
            end-of-archive marker is corrupt or truncated, ``"LINK_TARGET"``,
            ``"DUPLICATE_ENTRY"``, ``"ENTRY_NAME"``, ``"DECLARED_SIZE"``,
            ``"INTEGRITY"``, ``"ZIP_READER"`` (a failure of the ZIP reader or
            of the structural check built on it), ``"TAR_READER"`` or
            ``"SEVENZ_READER"`` (a failure of the TAR or 7z reader) for the
            refusal of that family; ``None`` otherwise.
        non_utf8_entry_path: The injectively escaped entry path (a backslash is
            ``\\x5C``, each invalid byte ``\\xNN``) when a listing or in-memory
            extraction refused an entry name that is not valid UTF-8; ``None``
            otherwise.
    """

    sub_code: _InvalidArchiveSubCode | None
    non_utf8_entry_path: str | None
