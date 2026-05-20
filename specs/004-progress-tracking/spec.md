---
aliases:
  - Progress Tracking Spec
  - ProgressCallback Spec
tags:
  - sdd
  - spec
  - progress
  - rust
created: 2026-05-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: Progress Tracking

> [!info] Metadata
> **Subsystem**: exarch-core / report, io
> **MSRV**: Rust 1.93.0
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Long-running archive operations (extraction of thousands of files, creation of
compressed archives) need a way to report progress to the caller without
coupling the core library to any specific UI framework or output format.
At the same time, zero-overhead extraction must remain possible when no
progress reporting is needed.

### Goal

Define a `ProgressCallback` trait with zero overhead when unused (`NoopProgress`)
and clear lifecycle semantics (entry start, bytes written, entry complete, all
complete), so that the CLI, Python, and Node.js layers can wire in their own
reporters without modifying `exarch-core`.

### Out of Scope

- Cancellation via the progress callback (potential future addition — see Open Questions)
- Estimated time remaining (ETA) calculation
- Thread-safe multi-producer progress reporting

## 2. User Stories

### US-001: Zero-Overhead Extraction

AS A Rust developer calling `extract_archive()` without a progress handler
I WANT extraction to have no overhead from progress tracking
SO THAT performance is not penalized in the common case

**Acceptance criteria:**
```
GIVEN extract_archive() called without a progress argument
THEN NoopProgress is used internally; no allocations or virtual dispatch per entry
```

### US-002: Per-Entry Progress Reporting

AS A CLI tool author
I WANT to receive callbacks as each archive entry is started, written to, and completed
SO THAT I can update a progress bar in real time

**Acceptance criteria:**
```
GIVEN a custom ProgressCallback implementation
WHEN extract_archive_with_progress() is called
THEN on_entry_start is called before writing the entry,
     on_bytes_written is called for each write chunk,
     on_entry_complete is called after the entry is fully written
```

### US-003: Completion Signal on Success Only

AS A caller using the progress callback for cleanup signaling
I WANT on_complete to be called only when extraction fully succeeds
SO THAT I can distinguish complete success from partial or failed extraction

**Acceptance criteria:**
```
GIVEN extraction that fails mid-archive
WHEN the error is returned
THEN on_complete has NOT been called
```

```
GIVEN extraction that succeeds for all entries
WHEN ExtractionReport is returned
THEN on_complete has been called exactly once
```

### US-004: Creation Progress

AS A developer using create_archive_with_progress()
I WANT progress callbacks during archive creation
SO THAT I can report file-packing progress to the user

**Acceptance criteria:**
```
GIVEN a custom ProgressCallback and create_archive_with_progress()
WHEN archive creation runs
THEN on_entry_start and on_entry_complete are called for each source file added
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | THE SYSTEM SHALL expose a `ProgressCallback` trait with methods: `on_entry_start(path, total, current)`, `on_bytes_written(bytes)`, `on_entry_complete(path)`, `on_complete()` | must |
| FR-041 | THE SYSTEM SHALL provide a `NoopProgress` implementation that satisfies `ProgressCallback` with no runtime overhead | must |
| FR-042 | `on_complete` SHALL NOT be called if extraction fails or is partial | must |
| FR-043 | `ProgressCallback` SHALL be `Send` so it can be used across thread boundaries (Node.js, Python) | must |
| FR-044 | Format handlers SHALL accept `&mut dyn ProgressCallback` and call it consistently for each entry; callbacks SHALL fire per-entry interleaved with actual I/O (not batched before or after) | must |
| FR-045 | `on_bytes_written` SHALL be called with the number of bytes written in the current chunk, not a cumulative total | must |
| FR-046 | `on_entry_start` SHALL receive the total number of entries (if known) and the current entry index | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `NoopProgress` must compile away to nothing; no virtual dispatch when `NoopProgress` is used as a concrete type |
| NFR-002 | Performance | Progress overhead measured in `exarch-core/benches/progress.rs` — must not exceed 5% throughput penalty |
| NFR-003 | Reliability | `on_complete` not called on failure — callers can rely on this for cleanup signaling |
| NFR-004 | Safety | `ProgressCallback: Send` is required for FFI use in Python and Node.js bindings |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ProgressCallback` | Trait for receiving archive operation progress events | Methods: `on_entry_start`, `on_bytes_written`, `on_entry_complete`, `on_complete` |
| `NoopProgress` | Zero-overhead implementation of `ProgressCallback` | All methods are no-ops; intended as the default |
| `ExtractionContext` | Per-extraction state passed through TAR helper functions to reduce arity | Holds references to config, options, output dir, and progress callback |
| `CountingWriter` | Wraps a `Write` impl and counts bytes written; feeds `on_bytes_written` | `inner: W`, `bytes_written: u64` |

### Trait Signature

```
ProgressCallback: Send
  on_entry_start(&mut self, path: &Path, total: usize, current: usize)
  on_bytes_written(&mut self, bytes: u64)
  on_entry_complete(&mut self, path: &Path)
  on_complete(&mut self)  // NOT called on failure; called only on full success
```

> [!note] v0.4.0 clarification
> `on_complete` is called only on successful completion. Implementors must not
> use it for cleanup — use the `Err` return path from `extract_archive` instead.

> [!note] ExtractionContext
> `ExtractionContext<'_, '_>` is a private TAR helper struct introduced in v0.4.0
> that groups `validator`, `dest`, `report`, `copy_buffer`, `dir_cache`, and
> `skip_duplicates` to reduce helper function arity. It is not part of the public
> API but is documented here because `ProgressCallback` is passed through it.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Extraction fails on first entry | Neither `on_entry_complete` nor `on_complete` called for that entry |
| Extraction fails after N successful entries | `on_entry_complete` called for the N successful entries; `on_complete` NOT called |
| `on_bytes_written` called with 0 bytes | Allowed; implementations must handle gracefully |
| Archive with unknown total entry count | `total` argument to `on_entry_start` is 0 |
| Progress callback panics | Panic propagates as normal Rust panic; not caught by exarch |
| Creation progress for large directories | `on_entry_start` called for each file; total is file count from walk |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `on_complete` not called on failure | Regression test (issue #170, fixed in v0.4.0) |
| SC-002 | Progress overhead vs no-progress | < 5% throughput penalty (measured in bench) |
| SC-003 | All format handlers (TAR, ZIP, 7z) call progress callbacks per-entry | Fixed in v0.4.0 (#170, #191) |

## 8. Agent Boundaries

### Always (without asking)
- Call `on_entry_start` before writing any bytes for an entry
- Call `on_entry_complete` after writing all bytes for an entry
- Call `on_complete` only on full success, never on error
- Pass `&mut dyn ProgressCallback` through `ExtractionContext` to avoid arity growth

### Ask First
- Adding new methods to `ProgressCallback` (trait breaking change)
- Adding cancellation support (architectural decision)

### Never
- Call `on_complete` on partial or failed extraction
- Depend on a specific `ProgressCallback` implementation inside `exarch-core`
- Remove `Send` bound from `ProgressCallback`

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `ProgressCallback` expose a cancellation mechanism (e.g., `on_entry_start` returns `bool` where `false` aborts extraction)? This would allow callers to cancel mid-archive without waiting for the operation to finish.]
- [NEEDS CLARIFICATION: Should `on_bytes_written` receive cumulative bytes or per-chunk bytes? Current spec says per-chunk — verify this matches CLI indicatif integration.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — format handlers that call progress callbacks
- [[005-cli/spec]] — indicatif-based `ProgressCallback` implementation
- [[006-python-bindings/spec]] — `PyProgressAdapter` and GIL interaction
- [[001-exarch-system/spec]] — original monolithic spec (archived)
