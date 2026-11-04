---
aliases:
  - Python Bindings Spec
  - PyO3 Bindings Spec
tags:
  - sdd
  - spec
  - python
  - ffi
  - rust
created: 2026-05-20
updated: 2026-11-04
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Python Bindings

> [!note] Revision 2026-11-04 (50-issue batch)
> Error classes with `code`, `SinkOptions`, per-kind entry classes, typed skips, `create_archive(format=, overwrite=)`, integer-limit boundary and lossless paths. See FR-094 to FR-103; rows that conflict (FR-072, FR-075, FR-079, FR-088, FR-089) are rewritten in place.

> [!info] Metadata
> **Subsystem**: exarch-python
> **MSRV**: Rust 1.98.0
> **Build**: maturin + pyo3 0.30
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Python developers building data pipelines, security tools, or CI systems need
safe archive operations without reimplementing the security checks available in
`exarch-core`. Wrapping the Rust library via PyO3 gives Python callers the same
guarantees while maintaining Python ergonomics (pathlib, exceptions, GIL semantics).

### Goal

Expose `exarch-core` operations as a Python module (`exarch`) using PyO3, with
proper GIL management during I/O, Pythonic error types, and path validation at
the Python boundary before any Rust code executes.

### Out of Scope

- Async Python interface (asyncio integration)
- NumPy or Pandas integration
- CLI wrapper for Python entry points (the `exarch-cli` crate handles the CLI)

## 2. User Stories

### US-001: Python Extraction

AS A Python developer
I WANT to call `exarch.extract_archive(path, output_dir)` from Python
SO THAT I benefit from the same security guarantees without reimplementing them

**Acceptance criteria:**
```
GIVEN a valid archive path and output directory as str or pathlib.Path
WHEN extract_archive(archive_path, output_dir) is called
THEN extraction runs with GIL released, files are extracted, and an ExtractionReport object is returned
```

### US-002: Path Validation at Python Boundary

AS A Python developer
I WANT invalid paths to be caught before calling into Rust
SO THAT I receive a clear Python exception for obvious mistakes

**Acceptance criteria:**
```
GIVEN a path containing null bytes
WHEN any exarch function is called with that path
THEN SecurityViolationError is raised immediately without calling into Rust core
```

```
GIVEN a path exceeding 4096 bytes
WHEN any exarch function is called with that path
THEN SecurityViolationError is raised immediately
```

> [!note] Unreleased (v0.6.0): boundary validation hoisted to `exarch-core`, exception type changed (#406)
> Both bindings previously hand-rolled null-byte/length checks independently (and had drifted:
> a full-scan fold vs. a short-circuiting check, inconsistent order). Both now call
> `exarch_core::validate_raw_path_str()` (checks length before scanning for a null byte, O(1)
> before the O(n) scan) and route its `ArchiveError::SecurityViolation` through the existing
> `convert_error()` used for every other rejection. **Breaking change**: Python now raises
> `SecurityViolationError` for null-byte/path-length rejections, not a bare `ValueError`.

### US-003: GIL Release During I/O

AS A Python developer in a multi-threaded application
I WANT extraction to release the GIL during the I/O phase
SO THAT other Python threads can run while archives are being extracted

**Acceptance criteria:**
```
GIVEN extract_archive() called without a progress callback
WHEN extraction runs
THEN the GIL is released for the duration of the Rust extraction call
```

```
GIVEN extract_archive() called with a Python progress callback
WHEN extraction runs
THEN the GIL is held (callback requires GIL to call Python)
```

### US-004: Pythonic Error Types

AS A Python developer
I WANT Rust ArchiveError variants to map to specific Python exception classes
SO THAT I can catch specific error types in a try/except block

**Acceptance criteria:**
```
GIVEN an archive with a path traversal entry
WHEN extract_archive() is called
THEN PathTraversalError (a subclass of ExarchError) is raised
```

### US-005: Python Config Classes

AS A Python developer
I WANT to construct SecurityConfig and CreationConfig using fluent Python classes
SO THAT I can customize security limits in idiomatic Python

**Acceptance criteria:**
```
GIVEN SecurityConfig().with_max_file_size(200 * 1024 * 1024).with_allow_symlinks(True)
WHEN passed to extract_archive()
THEN extraction respects those settings
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-070 | THE SYSTEM SHALL expose Python functions: `extract_archive`, `extract_archive_with_progress`, `create_archive`, `create_archive_with_progress`, `list_archive`, `verify_archive` | must |
| FR-071 | ALL Python functions SHALL accept `str` or `pathlib.Path` for path arguments | must |
| FR-072 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL raise `SecurityViolationError` (via the shared `exarch_core::BoundaryPath::parse()` (replaced `validate_raw_path_str`, #927) and the existing `convert_error()` path) at the Python boundary before calling into Rust (v0.6.0, #406 — previously a bare `ValueError`) | must |
| FR-073 | WHEN no Python progress callback is provided, THE SYSTEM SHALL release the GIL during extraction/creation | must |
| FR-074 | WHEN a Python progress callback is provided, THE SYSTEM SHALL NOT release the GIL (callback requires GIL to invoke Python) | must |
| FR-075 | Rust `ArchiveError` variants SHALL map to specific Python exception types; `SourceNotFound` → `SourceNotFoundError` (also `FileNotFoundError`), `SourceNotAccessible` → `SourceNotAccessibleError` (also `PermissionError`), `OutputExists` → `OutputExistsError` (also `FileExistsError`), `InvalidCompressionLevel` → `InvalidCompressionLevelError` and `InvalidConfiguration` → `InvalidConfigurationError` (both also `ValueError`; see FR-094); `PartialExtraction` → the specific inner exception type (e.g. `SymlinkEscapeError`, `QuotaExceededError`) with `files_extracted` and `bytes_written` attributes attached to that exception; since v0.8.0 the class, message and attributes all derive from one `exarch_core::ArchiveError::into_ffi_message()` (a typed `FfiKind` plus `PartialOutcome`), and the binding only picks the Python class per `FfiKind` (`FfiKind::Io(kind)` maps to the matching `OSError`; core `ReaderFormat` errors map to `UnknownFormatError` for an unrecognized format and `ValueError` otherwise) (#758, #768) | must |
| FR-076 | ALL Python exception types SHALL be subclasses of `ExarchError(Exception)` | must |
| FR-077 | `PySecurityConfig` and `PyCreationConfig` SHALL expose the same fluent builder API as the Rust counterparts | must |
| FR-078 | `PyExtractionReport`, `PyCreationReport`, `PyArchiveManifest`, and `PyVerificationReport` SHALL expose all fields as Python attributes | must |
| FR-079 | WHEN `CoreError::PartialExtraction` (a `Partial` consumed through `into_ffi_message()`, #907) is converted to a Python exception, THE SYSTEM SHALL attach `files_skipped: int`, `skipped` (FR-100) and `warnings: list[str]` (in addition to the existing `files_extracted`/`bytes_written`) — `exarch-core` has populated these on the report since v0.6.0 #505, and this binding was the one call site not yet forwarding them (v0.6.0, #508) | must |
| FR-080 | WHEN a Python progress callback raises during extraction or creation, THE SYSTEM SHALL capture the exception (not discard it) and, if the underlying operation otherwise succeeds, re-raise it to the caller carrying `files_extracted`/`files_added`, `bytes_written`, and a `progress_callback_error = True` marker attribute; if the operation also fails, the core error stays primary with the callback's exception chained via `__cause__` (v0.6.0, #489 — previously silently swallowed via `let _ = ...`) | must |
| FR-081 | ALL path-carrying `ArchiveError` variants SHALL be redacted for release-build Python exception messages via the shared `exarch_core::error::redaction` module, not a Python-crate-local copy; `PathTraversal`/`SymlinkEscape`/`HardlinkEscape`/`InvalidPermissions` (archive-relative, attacker-authored paths) SHALL keep the full path in both debug and release builds, while `SourceNotFound`/`SourceNotAccessible`/`OutputExists`/`UnknownFormat`/`Io` (host-derived paths) SHALL redact to filename-only (or `ErrorKind` description for `Io`) in release builds (v0.6.0, #453, #462, #463) | must |
| FR-082 | `verify_archive(archive_path, config=None, options=None)` SHALL accept a `VerificationOptions`; `VerificationOptions().with_integrity_check(budget=None)` decodes the payload to the decoder's EOF (default budget 500 MiB, independent of `max_total_size`; `ValueError` for a zero or negative budget), otherwise `integrity_status` is `"SKIPPED"` (v0.7.0, #670) | must |
| FR-083 | `VerificationReport` SHALL expose `integrity_status` (`"OK"`, `"FAILED"`, `"INCOMPLETE"`, `"SKIPPED"`), `integrity_gaps` (`None` unless the check ran, else `IntegrityGaps` with `counts`, `entries` of `UnverifiedEntry(path, reason)`, `omitted`, `total`) and `security_status`; report enum-like getters return strings annotated with `Literal` types in `exarch.pyi` (v0.7.0, #624, #672, #684) | must |
| FR-084 | `SecurityConfig` SHALL expose `with_parallel_decode_memory(size: int \| None)` (`None` decodes on one thread; default 128 MiB, 1 GiB for `permissive()`; `ValueError` for zero, negative or above 2**64 - 1) and `with_zip_consistency("enforce" \| "ignore")` (default `"enforce"`; `ValueError` for any other string), each with a matching property (v0.7.0, #671, #688) | must |
| FR-085 | `SecurityViolationError` SHALL carry a `relaxable_by` attribute: the stable id of the `SecurityConfig` setting that refused the entry (`"symlinks"`, `"hardlinks"`, `"solid_archives"`, `"banned_components"`, `"max_path_depth"`, `"windows_reserved_names"`, `"max_tar_metadata_bytes"`), or `None` (class default) when no setting relaxes the refusal (v0.7.0, #741, #757) | must |
| FR-086 | WHEN `CoreError::PartialExtraction` is converted, THE SYSTEM SHALL always attach `writes` (`"kept"`, `"rolled_back"` or, for an in-memory extraction, `"discarded"`) to the raised exception and attach `files_extracted`, `bytes_written`, `files_skipped` and `warnings` only when `writes == "kept"`; after an `ExtractionOptions.atomic` rollback, or an in-memory extraction that dropped its entries, the counters describe a discarded run and are omitted (v0.7.0, #735, #747; v0.8.0, #800, #808) | must |
| FR-087 | `ArchiveError::ZipBomb` SHALL map to `ZipBombError` (including an entry claiming data from zero compressed bytes, previously `InvalidArchiveError`), and `ArchiveError::ZipInconsistency` SHALL map to the new `ZipInconsistencyError`, a subclass of `SecurityViolationError` (v0.7.0, #653, #671) | must |
| FR-088 | THE SYSTEM SHALL expose in-memory functions that take and return bytes: `list_archive_bytes(data, config=None, format=None)`, `verify_archive_bytes(data, config=None, options=None, format=None)`, `extract_archive_to_memory(data, config=None, options=None, max_bytes=None, path_model=None, format=None)` (`options` is a `SinkOptions`, FR-096) returning `MemoryExtraction(report, entries)` of per-kind `MemoryEntry` classes (FR-097), and `create_archive_to_bytes(sources, format, config=None)` returning `CreatedArchive(data, report)`; `format` is detected from the leading bytes when `None`; `atomic` is unsupported for extraction; `max_bytes` defaults to the config's `max_total_size`; `path_model` is `"host"` or `"portable"`; `"SevenZ"` cannot be created; all validation is in `exarch-core` ([[020-reader-sink-and-in-memory-api/spec]]; v0.8.0, #776, #787, #790) | must |
| FR-089 | THE SYSTEM SHALL expose `extract_archive_to_memory_with_progress`, `list_archive_bytes_with_progress` and `verify_archive_bytes_with_progress`, each taking a `progress` callback of `(path, total, current, bytes_written)` (`total` is `None` while unknown, FR-100) with the GIL held; the in-memory functions without a callback SHALL release the GIL. A callback that raises after the operation succeeded SHALL discard the result and raise the callback's exception with `progress_callback_error = True` (an in-memory extraction also carries `writes == "discarded"`); if the operation failed, the core error stays primary with the callback's exception as `__cause__` (v0.8.0, #783, #784, #790) | must |
| FR-090 | A quota error for a single oversized file SHALL use the core wording `single file size` in the Python message (v0.8.0, #758, #768) | should |
| FR-091 | `InvalidArchiveError` and `SecurityViolationError` SHALL carry a `sub_code` attribute (a string id, `None` when the failure is not classified) and `InvalidConfiguration` errors a `setting` attribute, from the same `FfiKind` as the CLI `--json` fields (v0.8.0, #865, #870, #887, #894, #946) | must |
| FR-092 | The in-memory functions (`list_archive_bytes`, `verify_archive_bytes`, `extract_archive_to_memory`, their `_with_progress` variants and `extract_archive_to_callback`) SHALL accept `data` as bytes or as a binary file object, whose read failure surfaces unchanged (v0.8.0, #828) | must |
| FR-093 | THE SYSTEM SHALL expose `extract_archive_to_callback(data, on_entry, config=None, options=None, path_model=None, format=None)`, delivering each verified entry to a callable through `extract_reader_to_callback` and re-raising the callable's exception unchanged; a non-callable `on_entry` is a `TypeError` (v0.8.0, #842, #860, #884) | must |
| FR-094 | EVERY Python exception SHALL carry an instance attribute `code` (the stable `ErrorCode` id) set at raise time; `OutputExistsError(ArchiveError, FileExistsError)`, `SourceNotFoundError(ArchiveError, FileNotFoundError)`, `SourceNotAccessibleError(ArchiveError, PermissionError)`, `InvalidConfigurationError(ArchiveError, ValueError)` (with `setting`) and `InvalidCompressionLevelError(ArchiveError, ValueError)` SHALL be real classes built at module init with `builtins.type` over two bases and kept in a `PyOnceLock`, so both `except ArchiveError` and `except FileExistsError` (etc.) catch them; `_ErrorCode` and `_ConfigSetting` `Literal` aliases in `exarch.pyi` are under drift tests against core (#919) | must |
| FR-095 | `create_archive` and `create_archive_with_progress` SHALL take `format: str \| None` (an `ArchiveType` string shared with `create_archive_to_bytes`) and `overwrite: bool = True`; `overwrite=False` maps to `OutputFile::create_new` and raises `OutputExistsError`; the default is `Replace`, so `OutputExistsError` is raised only for `overwrite=False`; creation is staged and atomic (see [[021-create-staging-and-output-policy/spec]]); a refused exclude pattern raises `InvalidConfigurationError` with `setting == "exclude_pattern"` (#915, #931, #916) | must |
| FR-096 | The in-memory and callback functions SHALL take a frozen `SinkOptions(skip_duplicates=True, decode_reuse="off", decode_reuse_limit=None)` instead of `ExtractionOptions` (passing `ExtractionOptions` is a `TypeError`; a limit under `"off"` is a `ValueError`; the limit clamps to the core 256 MiB maximum) (#926) | must |
| FR-097 | `MemoryEntry` SHALL be a base class (`path`) with `MemoryFile` (`data`, `mode`), `MemoryDirectory`, `MemorySymlink` and `MemoryHardlink` (each only its own attributes, a `kind` class attribute from `MemoryEntryKind::as_str`), and `AnyMemoryEntry` in the stub; `ArchiveEntry` SHALL be a base class (`path`, `entry_type`, `compressed_size`, `mode`, `compression_ratio`) with `ArchiveFile` (the only class with `size`), `ArchiveDirectory`, `ArchiveSymlink` and `ArchiveHardlink`; link targets SHALL be `LinkTarget` subclasses by state (`RecordedLinkTarget.path`, `MissingLinkTarget`, `UnreadLinkTarget`, `UnreadableLinkTarget`, `OversizedLinkTarget.bytes`; a 7z symlink is `UnreadLinkTarget`); `is_symlink`, `is_hardlink`, `symlink_target` and `hardlink_target` are removed; drift tests cover every kind and link state (#923, #910) | must |
| FR-098 | Integer limit setters and builders SHALL accept a Python `int` (a `bool` is a `TypeError`) through core `positive_from_i128`, and negative, zero and oversized integers (including beyond `i128`) SHALL raise `InvalidConfigurationError` with `setting`, never `OverflowError`; `max_file_size`, `max_total_size` and `max_file_count` getters return `None` when unbounded; `parallel_decode_memory` errors carry `setting == "parallel_decode_memory"`; an out-of-range compression level raises `InvalidCompressionLevelError`; `max_solid_block_memory` is `None` and its setter raises `InvalidConfigurationError` while solid archives are refused; an unknown `zip_consistency`, creatable or archive `format`, `path_model`, `decode_reuse` or skip kind raises `InvalidConfigurationError` with `setting` (`zip_consistency`, `archive_format`/`creation_format`, `path_model`, `decode_reuse`, `skip_kind`) and problem `NotOneOf`, and `SinkOptions.decode_reuse_limit` of 0, negative, oversized (`TooLarge`) or with `decode_reuse="off"` (`NotSupported`) raises it with `decode_reuse_limit`; a `bool` limit or ratio is a `TypeError` and `10**400` as a ratio is `NotFinite` (#921, #913, #911) | must |
| FR-099 | `QuotaExceededError` and `ZipBombError` SHALL carry `sub_code` (quota kind or zip-bomb scope literal, including `SOLID_BLOCK_MEMORY`), and `InvalidArchiveError.sub_code` SHALL include `TAR_READER` and `SEVENZ_READER`, with `_QuotaSubCode`, `_ZipBombSubCode` and `_InvalidArchiveSubCode` literals under drift tests derived from `SubCode` (#918, #930, #896) | must |
| FR-100 | The progress callback SHALL receive `(path, total, current, bytes_written)` with `total` `None` while the count is unknown (TAR streams) and `current` counting from 1 (`ProgressCallbackFn = Callable[[str, int \| None, int, int], None]`); reports and partial-extraction exceptions SHALL carry `skipped` (`Skipped` with `total`, per-kind `counts`, a bounded `sample` of `Skip(kind, path, io_kind)`, `count(kind)`, `len()`; `_SkipKind` literal under a drift test), `files_skipped` stays derived, and `warnings` stay `list[str]` from the typed warnings (`Skip.io_kind` is the `io::ErrorKind` display text, not a stable code) (#904, #906) | must |
| FR-101 | Paths of entries, skips, verification issues, unverified entries and progress callbacks SHALL be converted from `&OsStr` with `os.fsdecode` (surrogateescape on Unix), so two entries never share a name and no `to_string_lossy` remains; the in-memory path still refuses a non-UTF-8 entry name; on Windows the conversion is not lossless for unpaired surrogates (#925) | must |
| FR-102 | `VerificationIssue` SHALL expose `code`, `sub_code`, `relaxable_by`, `setting` (from `FfiKind` and `SubCode`) and `mode` (the raw mode of an executable-file or invalid-permissions finding, from core `VerificationIssue::mode()`); `context` is removed (#899) | must |
| FR-103 | File inputs SHALL be split once, in `FileInput::new`, into `Seekable` and `Stream` (`StreamFile` has no `Seek`), and `parse_zip_consistency` SHALL share core's `parse_one` (#928) | should |
| FR-104 | A progress callback that raises during `create_archive_with_progress` SHALL cancel the creation through `ProgressCallback::is_cancelled`: nothing is committed, a previous archive stays, and the callback's exception wins over the core `Interrupted` error (`KeyboardInterrupt` included); extraction keeps its run-to-completion behavior (FR-080) (#931) | must |
| FR-105 | The stub `exarch.pyi` SHALL be checked by `mypy --strict` in CI (blocking) and `stubtest`: `_CreatableFormat` excludes `SevenZ`, `SinkOptions` has `__new__`, leaf classes are `@final`, `CreationConfig` exposes properties, the typing aliases (`AnyMemoryEntry`, `AnyArchiveEntry`, `AnyLinkTarget`, `ProgressCallbackFn`) are importable at runtime, and sub-code and kind literals are derived by drift tests from core consts (`SubCode::QUOTA_ALL`, `ZIP_BOMB_ALL`); `ArchiveError.code` stays an instance attribute | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | `unsafe impl Send for PyProgressAdapter` is the only justified `unsafe` in the Python crate; must be documented |
| NFR-002 | Performance | GIL is released during I/O when no progress callback is provided |
| NFR-003 | Compatibility | Built with `maturin` and `pyo3` abi3 feature for broad Python version support |
| NFR-004 | Testability | Python tests run via `pytest` with `maturin develop` — excluded from `cargo nextest` |
| NFR-005 | Correctness | All security logic stays in `exarch-core`; Python crate contains only type mapping and boundary validation |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `PySecurityConfig` | Python class wrapping `SecurityConfig` | Fluent builder methods all use `with_` prefix: `with_max_file_size()`, `with_allow_symlinks()`, `with_allow_hardlinks()`, `with_allow_absolute_paths()`, `with_allow_world_writable()`, `with_allow_solid_archives()`, etc.; scalar getters (`max_file_size`, `max_total_size`, etc.) return values directly |
| `PyCreationConfig` | Python class wrapping `CreationConfig` | Same fluent builder methods; `with_max_file_size(size: int \| None)` takes `None` for no limit and refuses `0` with `ValueError` (#893, #946) |
| `PyExtractionReport` | Python class wrapping `ExtractionReport` | `files_extracted`, `bytes_written`, `duration`, `warnings`, `skipped`, `files_skipped` |
| `PyCreationReport` | Python class wrapping `CreationReport` | `files_added`, `bytes_written`, `duration`, `skipped`, `warnings` |
| `Skipped` / `Skip` | Typed skip accounting (#906) | `total`, `counts`, `sample`, `count(kind)`, `len()` / `kind`, `path`, `io_kind` |
| `SinkOptions` | Frozen options of the in-memory and callback functions (#926) | `skip_duplicates`, `decode_reuse`, `decode_reuse_limit` |
| `ArchiveEntry` family | Listing entries by kind (#923, #910) | `ArchiveFile`, `ArchiveDirectory`, `ArchiveSymlink`, `ArchiveHardlink`; `LinkTarget` subclasses |
| `PyArchiveManifest` | Python class wrapping `ArchiveManifest` | `total_entries`, `total_size`, `format`, `entries` |
| `PyVerificationReport` | Python class wrapping `VerificationReport` | `status`, `issues`, `total_entries`, `total_size`, `integrity_status`, `integrity_gaps`, `security_status` |
| `PyVerificationOptions` | Python class `VerificationOptions` wrapping core `VerificationOptions` (v0.7.0, #670) | `with_integrity_check(budget)`, `integrity_check`, `decompression_budget` |
| `PyIntegrityGaps` / `PyUnverifiedEntry` | Python classes `IntegrityGaps` / `UnverifiedEntry` wrapping the report's unverified-entry data (v0.7.0, #672) | `counts`, `entries`, `omitted`, `total` / `path`, `reason` |
| `MemoryExtraction` / `MemoryEntry` / `CreatedArchive` | Results of the in-memory functions (v0.8.0; per-kind classes since #923) | `report`, `entries` / `MemoryFile`, `MemoryDirectory`, `MemorySymlink`, `MemoryHardlink` (`kind` class attribute) / `data`, `report` |
| `PyProgressAdapter` | Internal adapter calling Python progress callbacks from Rust | Holds `PyObject` reference; `unsafe impl Send` |

### Python Exception Hierarchy

```
ExarchError(Exception)           # catch-all alias; same class as ArchiveError
ArchiveError(Exception)          # base exception (renamed from ExtractionError in v0.4.1); every instance has `code`
  OutputExistsError(ArchiveError, FileExistsError)            # #919
  SourceNotFoundError(ArchiveError, FileNotFoundError)        # #919
  SourceNotAccessibleError(ArchiveError, PermissionError)     # #919
  InvalidConfigurationError(ArchiveError, ValueError)         # #919, carries `setting`
  InvalidCompressionLevelError(ArchiveError, ValueError)      # #919
  PathTraversalError(ArchiveError)      # may carry files_extracted, bytes_written
  SymlinkEscapeError(ArchiveError)      # may carry files_extracted, bytes_written
  HardlinkEscapeError(ArchiveError)     # may carry files_extracted, bytes_written
  ZipBombError(ArchiveError)            # may carry files_extracted, bytes_written
  QuotaExceededError(ArchiveError)      # may carry files_extracted, bytes_written
  SecurityViolationError(ArchiveError)  # may carry files_extracted, bytes_written; relaxable_by (default None)
    ZipInconsistencyError(SecurityViolationError)  # ZIP structure read differently by different tools
  InvalidPermissionsError(ArchiveError) # may carry files_extracted, bytes_written
  UnsupportedFormatError(ArchiveError)
    UnknownFormatError(UnsupportedFormatError)  # raised for CoreError::UnknownFormat
  InvalidArchiveError(ArchiveError)
```

> [!note] v0.4.1: error rename and `UnknownFormatError`
> The Python base exception is now `exarch.ArchiveError` (was `exarch.ExtractionError`).
> `UnknownFormatError` is a distinct subclass of `UnsupportedFormatError`, raised when the
> archive format cannot be identified from path or magic bytes. Callers catching the broader
> `UnsupportedFormatError` continue to work unchanged; those that need to distinguish "format
> unknown" from "format known but unsupported" can catch the narrower type (#260).

The `files_extracted` and `bytes_written` attributes are present on the raised
exception when `exarch-core` wraps the inner error in `CoreError::PartialExtraction`
(i.e. when at least one file was written to disk before the security check failed).
Since v0.7.0 these counters are attached only while the written files remain on disk
(`writes == "kept"`); an atomic rollback attaches `writes == "rolled_back"` and no counters.
Use `getattr(e, "writes", None) == "kept"` to detect files left on disk.
`ExarchError` is the catch-all base for any extraction failure.

> [!note] Error mapping corrections (#209, #210, #251)
> - `SourceNotFound`, `SourceNotAccessible`, and `OutputExists` now raise
>   `PyIOError` (was `InvalidArchiveError`).
> - `InvalidCompressionLevel` and `InvalidConfiguration` now raise
>   `PyValueError` (was `InvalidArchiveError`).
> - In v0.4.0, `PartialExtraction` incorrectly collapsed all partial-extraction
>   failures into a generic `PartialArchiveError` (#216). Fixed in v0.4.1
>   (#251): the specific inner exception type is raised (e.g. `SymlinkEscapeError`)
>   with `files_extracted` and `bytes_written` attached directly to it (#210).
>   `PartialArchiveError` has been removed from the public API.
> These corrections allow Python callers to distinguish I/O failures, validation
> errors, and archive corruption with specific `except` clauses.

### Python API Surface

```python
# Module: exarch

def extract_archive(archive_path, output_dir, config=None, options=None) -> ExtractionReport
def extract_archive_with_progress(archive_path, output_dir, config=None, progress=None) -> ExtractionReport
    # GIL held when progress callback is provided; released otherwise
def create_archive(output_path, sources, config=None, format=None, overwrite=True) -> CreationReport
def create_archive_with_progress(output_path, sources, config=None, progress=None, format=None, overwrite=True) -> CreationReport
def list_archive(archive_path, config=None) -> ArchiveManifest
def verify_archive(archive_path, config=None, options=None) -> VerificationReport

# In-memory (v0.8.0): bytes in, bytes or entries out; nothing is written to disk
def list_archive_bytes(data, config=None, format=None) -> ArchiveManifest
def verify_archive_bytes(data, config=None, options=None, format=None) -> VerificationReport
def extract_archive_to_memory(data, config=None, options: SinkOptions | None = None, max_bytes=None, path_model=None, format=None) -> MemoryExtraction
def create_archive_to_bytes(sources, format, config=None) -> CreatedArchive
# *_with_progress variants: extract_archive_to_memory_with_progress, list_archive_bytes_with_progress, verify_archive_bytes_with_progress

class VerificationOptions:
    def with_integrity_check(self, budget: int | None = None) -> VerificationOptions

class SinkOptions:  # frozen
    def __init__(self, skip_duplicates: bool = True, decode_reuse: str = "off", decode_reuse_limit: int | None = None)

class ExtractionOptions:
    def with_atomic(self, atomic: bool = True) -> ExtractionOptions
    def with_skip_duplicates(self, skip: bool = True) -> ExtractionOptions
    @property
    def atomic(self) -> bool
    @atomic.setter
    def atomic(self, value: bool) -> None
    @property
    def skip_duplicates(self) -> bool
```

> [!note] v0.5.0: `ExtractionOptions` and `extract_archive_with_progress` added
> Both `extract_archive` and `extract_archive_with_progress` accept an optional `options`
> parameter of type `ExtractionOptions`. `ExtractionOptions.atomic` triggers staging-directory
> extraction with atomic rename; `ExtractionOptions.skip_duplicates` (default `True`) skips
> duplicate entries. `with_atomic` and `with_skip_duplicates` are the fluent builder methods.

> [!note] v0.5.0: builder method naming
> All Python `SecurityConfig` builder methods that previously omitted `with_` (`allow_symlinks`,
> `allow_hardlinks`, `allow_absolute_paths`, `allow_world_writable`, `allow_solid_archives`)
> have been renamed to `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`,
> `with_allow_world_writable`, `with_allow_solid_archives` to match the `with_` prefix
> convention. Update all call sites accordingly (#354).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path is `None` | `TypeError` raised by PyO3 before boundary check |
| Path contains null byte | `SecurityViolationError` at Python boundary (v0.6.0, #406 — was `ValueError`) |
| Path exceeds 4096 bytes | `SecurityViolationError` at Python boundary (v0.6.0, #406 — was `ValueError`) |
| Path is `pathlib.Path` | Converted to `str` via `.as_os_str()` before Rust call |
| Rust returns `ArchiveError::PathTraversal` | `PathTraversalError` raised in Python; full archive-relative path retained even in release builds (v0.6.0, #462) |
| Rust returns `ArchiveError::SourceNotFound` or `OutputExists` | `SourceNotFoundError` / `OutputExistsError` raised (also `FileNotFoundError` / `FileExistsError`, so `except OSError` still catches them); host path redacted to filename-only in release builds |
| Rust returns `ArchiveError::InvalidCompressionLevel` or `InvalidConfiguration` | `InvalidCompressionLevelError` / `InvalidConfigurationError` raised (also `ValueError`) |
| An integer limit that is negative, zero or beyond `i128`; a `bool` limit | `InvalidConfigurationError` with `setting` (never `OverflowError`); `TypeError` for a `bool` (#921) |
| `create_archive(out, [dir_containing_out])` | The output and its staged file are skipped; no loop (#931) |
| `create_archive(..., overwrite=False)` onto an existing file | `OutputExistsError`; file untouched (#931) |
| Rust returns `ArchiveError::PartialExtraction` | The specific inner exception (e.g. `SymlinkEscapeError`) is raised; `files_extracted`, `bytes_written`, `files_skipped`, and `warnings` attributes are attached (v0.6.0, #508) together with `writes == "kept"`; detect files left on disk via `getattr(e, "writes", None) == "kept"` |
| Progress callback raises Python exception | Captured, not discarded (v0.6.0, #489); extraction/creation still runs to completion (no cancellation signal), then the exception propagates on success with `progress_callback_error = True`, or chains onto the core error via `__cause__` on failure |
| In-memory extraction fails after collecting entries | The inner exception carries `writes == "discarded"` and none of the counter attributes (v0.8.0, #800) |
| `extract_archive_to_memory` with `atomic` set, `max_bytes` zero or not a positive whole number, an unknown `format` or `path_model`, or `create_archive_to_bytes` with `"SevenZ"` | `ValueError` (v0.8.0) |
| Format cannot be detected from the bytes | `UnknownFormatError` (v0.8.0) |
| Rust returns `ArchiveError::PartialExtraction` after an atomic rollback | The inner exception carries `writes == "rolled_back"` and none of the counter attributes (v0.7.0, #747) |
| Symlink entry over an existing symlink with a different target, overwrite enabled | Builtin `OSError` (`ELOOP`), not `SymlinkEscapeError` (v0.7.0, #752) |
| Rust returns `ArchiveError::SecurityViolation` that a setting relaxes | `SecurityViolationError` with `relaxable_by` set to the setting id (v0.7.0, #741, #757) |
| GIL state with progress callback | GIL held throughout; no concurrent Python threads during extraction |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All Python functions return correct report objects | `pytest` test coverage for each function |
| SC-002 | GIL released when no callback provided | Verified by thread concurrency test |
| SC-003 | All `ArchiveError` variants map to Python exceptions | Test for each variant |
| SC-004 | Path boundary validation catches null bytes and long paths | Unit tests at Python boundary |
| SC-005 | `maturin develop` + `pytest` passes on CI | CI job for Python crate |

## 8. Agent Boundaries

### Always (without asking)
- Validate paths at the Python boundary before calling into Rust
- Release GIL during Rust calls when no Python progress callback is present
- Map every `ArchiveError` variant to a Python exception subclass of `ExarchError`
- Keep all security logic in `exarch-core`; Python crate contains only type mapping

### Ask First
- Adding new Python-facing functions not yet in `exarch-core`
- Changing `PyProgressAdapter`'s `unsafe impl Send` justification
- Adding new Python exception types

### Never
- Implement security validation in the Python crate
- Hold the GIL during long I/O operations without a progress callback
- Expose `ArchiveError` as a raw Rust type to Python callers

## 9. Open Questions

- [NEEDS CLARIFICATION: Should an async Python interface (asyncio) be provided via `pyo3-asyncio` in a future version?]

> [!note] Resolved in v0.3.1
> Python version range: minimum Python 3.10. Python 3.9 support was dropped when it reached
> EOL in October 2025. The abi3 wheel covers 3.10–3.14+.

## 10. See Also

- [[constitution]] — project principles (GIL management)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — security pipeline invoked by Python bindings
- [[003-config-api/spec]] — `SecurityConfig` and `CreationConfig` types
- [[004-progress-tracking/spec]] — `ProgressCallback` and `PyProgressAdapter`
- [[020-reader-sink-and-in-memory-api/spec]] — core API behind the in-memory functions
- [[021-create-staging-and-output-policy/spec]] — `format`, `overwrite` and staged creation
- [[001-exarch-system/spec]] — original monolithic spec (archived)
