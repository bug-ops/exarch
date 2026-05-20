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
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
---

# Feature: Python Bindings

> [!info] Metadata
> **Subsystem**: exarch-python
> **MSRV**: Rust 1.93.0
> **Build**: maturin + pyo3 0.28
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
THEN ValueError is raised immediately without calling into Rust core
```

```
GIVEN a path exceeding 4096 bytes
WHEN any exarch function is called with that path
THEN ValueError is raised immediately
```

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
I WANT Rust ExtractionError variants to map to specific Python exception classes
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
GIVEN SecurityConfig().max_file_size(200 * 1024 * 1024).allow_symlinks(True)
WHEN passed to extract_archive()
THEN extraction respects those settings
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-070 | THE SYSTEM SHALL expose Python functions: `extract_archive`, `create_archive`, `create_archive_with_progress`, `list_archive`, `verify_archive` | must |
| FR-071 | ALL Python functions SHALL accept `str` or `pathlib.Path` for path arguments | must |
| FR-072 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL raise `ValueError` at the Python boundary before calling into Rust | must |
| FR-073 | WHEN no Python progress callback is provided, THE SYSTEM SHALL release the GIL during extraction/creation | must |
| FR-074 | WHEN a Python progress callback is provided, THE SYSTEM SHALL NOT release the GIL (callback requires GIL to invoke Python) | must |
| FR-075 | Rust `ExtractionError` variants SHALL map to specific Python exception types; `SourceNotFound`/`OutputExists` → `PyIOError`; `InvalidCompressionLevel`/`InvalidConfiguration` → `PyValueError`; `PartialExtraction` → `PartialExtractionError` with `files_extracted` and `bytes_written` attributes | must |
| FR-076 | ALL Python exception types SHALL be subclasses of `ExarchError(Exception)` | must |
| FR-077 | `PySecurityConfig` and `PyCreationConfig` SHALL expose the same fluent builder API as the Rust counterparts | must |
| FR-078 | `PyExtractionReport`, `PyCreationReport`, `PyArchiveManifest`, and `PyVerificationReport` SHALL expose all fields as Python attributes | must |

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
| `PySecurityConfig` | Python class wrapping `SecurityConfig` | Same fluent builder methods: `max_file_size()`, `allow_symlinks()`, etc. |
| `PyCreationConfig` | Python class wrapping `CreationConfig` | Same fluent builder methods |
| `PyExtractionReport` | Python class wrapping `ExtractionReport` | `files_extracted`, `bytes_written`, `duration`, `warnings` |
| `PyCreationReport` | Python class wrapping `CreationReport` | `files_added`, `bytes_written`, `duration` |
| `PyArchiveManifest` | Python class wrapping `ArchiveManifest` | `total_entries`, `total_size`, `format`, `entries` |
| `PyVerificationReport` | Python class wrapping `VerificationReport` | `status`, `issues`, `total_entries` |
| `PyProgressAdapter` | Internal adapter calling Python progress callbacks from Rust | Holds `PyObject` reference; `unsafe impl Send` |

### Python Exception Hierarchy

```
ExarchError(Exception)
  PathTraversalError(ExarchError)
  SymlinkEscapeError(ExarchError)
  HardlinkEscapeError(ExarchError)
  ZipBombError(ExarchError)
  QuotaExceededError(ExarchError)
  UnsupportedFormatError(ExarchError)
  InvalidArchiveError(ExarchError)
  SecurityViolationError(ExarchError)
  InvalidPermissionsError(ExarchError)
  PartialExtractionError(ExarchError)   # exposes files_extracted, bytes_written
```

> [!note] Error mapping corrections in v0.4.0 (#209)
> - `SourceNotFound`, `SourceNotAccessible`, and `OutputExists` now raise
>   `PyIOError` (was `InvalidArchiveError`).
> - `InvalidCompressionLevel` and `InvalidConfiguration` now raise
>   `PyValueError` (was `InvalidArchiveError`).
> - `PartialExtractionError` now exposes `files_extracted` and `bytes_written`
>   attributes for caller inspection (#210).
> These corrections allow Python callers to distinguish I/O failures, validation
> errors, and archive corruption with specific `except` clauses.

### Python API Surface

```python
# Module: exarch

def extract_archive(archive_path, output_dir, config=None) -> ExtractionReport
def create_archive(output_path, sources, config=None) -> CreationReport
def create_archive_with_progress(output_path, sources, config=None, progress=None) -> CreationReport
def list_archive(archive_path, config=None) -> ArchiveManifest
def verify_archive(archive_path, config=None) -> VerificationReport
```

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path is `None` | `TypeError` raised by PyO3 before boundary check |
| Path contains null byte | `ValueError` at Python boundary |
| Path exceeds 4096 bytes | `ValueError` at Python boundary |
| Path is `pathlib.Path` | Converted to `str` via `.as_os_str()` before Rust call |
| Rust returns `ExtractionError::PathTraversal` | `PathTraversalError` raised in Python |
| Rust returns `ExtractionError::SourceNotFound` or `OutputExists` | `PyIOError` raised (not `InvalidArchiveError`) |
| Rust returns `ExtractionError::InvalidCompressionLevel` or `InvalidConfiguration` | `PyValueError` raised (not `InvalidArchiveError`) |
| Rust returns `ExtractionError::PartialExtraction` | `PartialExtractionError` raised; `files_extracted` and `bytes_written` attributes populated |
| Progress callback raises Python exception | Exception propagates through `PyProgressAdapter`; extraction aborted |
| GIL state with progress callback | GIL held throughout; no concurrent Python threads during extraction |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All Python functions return correct report objects | `pytest` test coverage for each function |
| SC-002 | GIL released when no callback provided | Verified by thread concurrency test |
| SC-003 | All `ExtractionError` variants map to Python exceptions | Test for each variant |
| SC-004 | Path boundary validation catches null bytes and long paths | Unit tests at Python boundary |
| SC-005 | `maturin develop` + `pytest` passes on CI | CI job for Python crate |

## 8. Agent Boundaries

### Always (without asking)
- Validate paths at the Python boundary before calling into Rust
- Release GIL during Rust calls when no Python progress callback is present
- Map every `ExtractionError` variant to a Python exception subclass of `ExarchError`
- Keep all security logic in `exarch-core`; Python crate contains only type mapping

### Ask First
- Adding new Python-facing functions not yet in `exarch-core`
- Changing `PyProgressAdapter`'s `unsafe impl Send` justification
- Adding new Python exception types

### Never
- Implement security validation in the Python crate
- Hold the GIL during long I/O operations without a progress callback
- Expose `ExtractionError` as a raw Rust type to Python callers

## 9. Open Questions

- [NEEDS CLARIFICATION: Should an async Python interface (asyncio) be provided via `pyo3-asyncio` in a future version?]
- [NEEDS CLARIFICATION: What Python version range does the abi3 build target? (e.g., 3.8+)]

## 10. See Also

- [[constitution]] — project principles (GIL management)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — security pipeline invoked by Python bindings
- [[003-config-api/spec]] — `SecurityConfig` and `CreationConfig` types
- [[004-progress-tracking/spec]] — `ProgressCallback` and `PyProgressAdapter`
- [[001-exarch-system/spec]] — original monolithic spec (archived)
