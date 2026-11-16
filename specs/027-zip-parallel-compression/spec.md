---
aliases:
  - ZIP Parallel Compression
  - Parallel ZIP Create
tags:
  - sdd
  - spec
  - zip
  - performance
  - creation
created: 2026-11-08
updated: 2026-11-16
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: Opt-in Parallel Compression for ZIP Creation

> [!info] Metadata
> **Issue**: #1027 (batch PR #1230 branch `feat/1230-batch-11-issues`)
> **Decision**: implement (user decision, 2026-11-15): byte identity between sequential and parallel output, CLI `--threads`.
> **Status**: implemented in the batch PR #1230, unreleased. Measured on a loaded host with 2000 files of 128 KiB (deflate): `Sequential` +1% against the base, `Threads(4)` median 3.5x (worst round 2.7x). Deviations are listed in section 9.

> [!abstract]
> `create_archive` compresses ZIP entries one at a time. This spec adds `Parallelism::{Sequential, Threads(NonZeroUsize)}` on `CreationConfig` and `create --threads <N>`. Both modes route regular files through the same prepared-entry path, so the output depends on the tree and the configuration only, never on the thread count. Sequential output bytes change once relative to 0.10 (documented breaking note).

## 1. Overview

### Problem Statement

For a large many-file DEFLATE or zstd ZIP, compression dominates and entries are independent. The `zip` crate (workspace `~9.4`, stable API in 9.4.1) provides `ZipFileBuilder` and `add_prepared_file`. exarch must keep deterministic output, exact quota and file-count accounting, the staged-create durability model, bounded memory, ordered progress and cancellation, and the read-through-pinned-parent source rule (spec 021 FR-048 to FR-052).

### Goal

With `Threads(n)`, ZIP creation wall-clock time scales with the cores allowed, and the archive is byte-identical to the one produced with `Sequential` for the same input and configuration.

### Out of Scope

- Parallel extraction, verification or listing.
- Parallel creation for TAR and 7z; parallelism inside one entry.
- Changing the default (sequential), new compression methods or levels.
- Python and Node.js exposure (bindings stay sequential).

## 2. User Stories

### US-001: Faster creation of large trees

AS A user archiving a large many-file tree to ZIP
I WANT to opt in to multi-threaded compression
SO THAT creation time drops with the cores I allow.

**Acceptance criteria:**
```
GIVEN the 256 MiB deflate fixture on an idle host with at least 4 cores
WHEN I create a ZIP with Threads(4) instead of Sequential
THEN wall-clock time is at least 2.5 times lower
```

### US-002: Reproducible archives regardless of thread count

AS A release engineer
I WANT identical bytes from Sequential and any Threads(n)
SO THAT checksums do not depend on the build host.

**Acceptance criteria:**
```
GIVEN the same tree and CreationConfig apart from parallelism
WHEN I create with Sequential, Threads(1), Threads(2), Threads(4), Threads(8)
THEN all outputs are byte-identical
```

### US-003: No surprise threads in a library

AS A library embedder
I WANT parallelism to be explicit and bounded
SO THAT exarch never spawns a global pool or oversubscribes my host.

**Acceptance criteria:**
```
GIVEN a CreationConfig without parallelism set
WHEN create_archive runs
THEN no worker thread is spawned
```

### US-004: Same safety under parallelism

AS A security-conscious operator
I WANT quota, file-count and memory limits enforced exactly
SO THAT threads never let an input exceed the limits.

**Acceptance criteria:**
```
GIVEN a total-size or file-count limit that the input exceeds
WHEN creation runs with Threads(n)
THEN it fails with the same error at the same entry as Sequential and commits no output
```

## 3. Functional Requirements

### FR-001

WHEN parallelism is not set THE SYSTEM SHALL create ZIP archives on the calling thread with no worker thread.

**Priority**: must

### FR-002

`Parallelism` SHALL be a typed `#[non_exhaustive]` enum, `Sequential` (default) and `Threads(NonZeroUsize)`, on `CreationConfig`; there SHALL be no `usize` sentinel for "auto" and no boolean.

**Priority**: must

### FR-003

THE SYSTEM SHALL route every regular file whose `fstat` size, taken on the handle opened on the main thread, is at most `PREPARED_ENTRY_LIMIT` (8 MiB) through `ZipFileBuilder` and `PreparedZipFile` / `add_prepared_file` in both modes; larger files SHALL use the streaming writer in both modes. Output bytes therefore depend on (tree, config) only.

**Priority**: must

### FR-004

WHEN parallelism is `Threads(n)` THE SYSTEM SHALL prepare entries on at most `min(n, available_parallelism())` worker threads under a scope owned by the single `create_archive` call, with at most 2 times the worker count of entries in flight, and SHALL NOT use a process-global pool. `Threads(n)` is clamped and the clamp is documented.

**Priority**: must

### FR-005

THE SYSTEM SHALL write entries in the same order, with the same headers, timestamps and compressed bytes, whatever the thread scheduling.

**Priority**: must

### FR-006

Sources SHALL be opened and verified on the main thread in walk order (spec 021 FR-048, FR-049); workers SHALL receive the open file and SHALL NOT re-open by path. Both routes SHALL read through the exact-length reader (FR-051); a file that grows or shrinks after the stat SHALL yield `ArchiveError::SourceChanged` in both modes.

**Priority**: must

### FR-007

Quota, file count, progress, cancellation and the first error SHALL be handled on the main thread in archive order, so a limit failure occurs at the same entry and with the same error as `Sequential`, `ProgressCallback` is never invoked concurrently, and when several entries fail the earliest in archive order is returned.

**Priority**: must

### FR-008

WHEN cancellation is requested THE SYSTEM SHALL stop dispatching, discard in-flight work and return the same cancellation error as `Sequential`, with no committed output.

**Priority**: must

### FR-009

Output SHALL go through the staged-create path of spec 021 (staged file, fsync, rename) unchanged.

**Priority**: must

### FR-010

A panic of a worker SHALL surface on the calling thread instead of hanging the call. Symlinks, hardlinks, directories and special files SHALL be processed on the sequential path (no compression is involved). On `wasm32-wasip1` and from the Python and Node bindings the sequential path SHALL be used whatever is configured.

**Priority**: must

### FR-011

THE CLI SHALL accept `create --threads <N>` as a non-zero `u16`; absent means sequential. THE docs SHALL state the clamp of FR-004.

**Priority**: must

### FR-012

THE zip-prepared-entry APIs SHALL be used only through one internal module of `exarch-core/src/creation`.

**Priority**: should

## 4. Non-Functional Requirements

### NFR-PERF-001

`Sequential` throughput SHALL regress by at most 10% against the pre-change baseline (`benches/creation.rs`). `Threads(4)` SHALL be at least 2.5 times faster on the 256 MiB deflate prototype on an idle host. If the sequential gate fails, the fallback design (byte identity across n of at least 1 only, with `Sequential` untouched) goes back to the user.

### NFR-DET-001

Output bytes are a pure function of the tree and the `CreationConfig` content, excluding parallelism. The walk is sorted by file name inside each directory for every format (TAR and ZIP) and a ZIP entry stores the source modification time, so two runs agree. The sequential bytes differ once from 0.10 (CHANGELOG breaking note).

### NFR-MEM-001

Peak extra memory is bounded by 2 times the workers times 8 MiB.

### NFR-SEC-001

No change to path validation, symlink and hardlink handling, compression-ratio checks or permission sanitization; all run before an entry is dispatched.

### NFR-DEP-001

No new dependency: `std::thread::scope`, a bounded `sync_channel` and an archive-order reorder buffer; the `zip` version is not pinned exactly.

### NFR-PORT-001

Builds and passes on all CI targets, including `wasm32-wasip1` and Windows.

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Parallelism` | Typed enum on `CreationConfig` | `Sequential` (default), `Threads(NonZeroUsize)` |
| Prepared entry | A compressed entry awaiting its turn | archive index, compressed bytes (at most 8 MiB source) |
| Reorder buffer | Bounded holding area | at most 2 times workers |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `Threads(1)` | Identical output; may run inline |
| `Threads(n)` above entries or cores | Workers clamped; no error |
| File larger than 8 MiB among small ones | Streams; others prepared |
| Head-of-line entry slow | Workers stall on backpressure; memory bounded |
| Worker or source error | Earliest failing entry in archive order is returned; staged output discarded |
| Cancellation | Prompt stop; no output |
| Source grows or shrinks after the stat | `SourceChanged` in both modes |
| Quota exceeded | Same entry and error as `Sequential` |
| wasip1, Python, Node | Sequential; setting ignored and documented |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Byte equality across `Sequential`, 1, 2, 4, 8 over the corpus | 100% identical |
| SC-002 | `Threads(4)` versus `Sequential` on the 256 MiB deflate prototype | at least 2.5 times |
| SC-003 | `Sequential` versus the B0 baseline | at most 10% slower |
| SC-004 | Limit, cancellation, error-order and growing-source tests | same outcome as `Sequential` |
| SC-005 | CI on wasip1, Windows, bindings | green |

## 8. Agent Boundaries

### Always (without asking)
- Add byte-identity tests between `Sequential` and `Threads(n)`.
- Run `rust-security-maintenance` and `rust-performance-engineer`.
- Update `skills/exarch-cli/SKILL.md` for the flag, verified against the binary.

### Ask First
- Adding a dependency, exposing parallelism in a binding, changing the 8 MiB limit.

### Never
- Use the process-global pool; let bytes, order or error selection depend on scheduling; bypass `QuotaTracker`, path validation or the staged-create sequence; re-open sources by path in a worker.

## 9. Open Questions

None open. Results of the benchmark gates are recorded in `.local/testing/benchmarks.md`.

### Deviations (approved by the lead during the batch)

| Requirement | Specified | Implemented |
|-------------|-----------|-------------|
| FR-005, NFR-DET-001 | same order and headers as today | the walk is now sorted by file name inside each directory for every format, and ZIP entries store the source mtime (UTC, DOS range, epoch fallback; a source mtime after the DOS range is clamped to its last representable second, 2107-12-31 23:59:58, not to the epoch fallback, #1263) instead of "now at start"; both are needed for byte identity and are part of the CHANGELOG breaking note |
| FR-007 | progress per entry | a prepared entry reports one `on_bytes_written` call with the entry size (per-entry granularity) |
| FR-006 | `SourceChanged` in both modes | for a prepared entry it is raised by the exact-length reader inside the worker job; the source tests for the grow and shrink cases use files above 8 MiB (stream route), and the prepared route is covered by unit tests |
| NFR-PERF-001 | gates on an idle host | measured on a loaded host (see the status note); a rerun on an idle host is recommended before release |

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[021-create-staging-and-output-policy/spec]] — staged create and source-read rules
- [[005-cli/spec]] — `create --threads`
- [[027-zip-parallel-compression/plan]] — plan and Contracts
