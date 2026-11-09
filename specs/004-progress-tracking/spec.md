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
updated: 2026-11-09
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Progress Tracking

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> `on_entry_start` takes an `EntryPosition` (#904); skips are typed and counted per kind in the reports (#906); the progress-variant free functions became `with_progress` on request types (#912); reports are `#[non_exhaustive]` (#905); the CLI bar for `create` follows the real total (#942).

> [!info] Metadata
> **Subsystem**: exarch-core / report, io
> **MSRV**: Rust 1.99.1
> **Source**: extracted from [[001-exarch-system/spec]]

> [!note] Batch #981 amendments
> Cancellation now covers extraction, list, verify and creation through one per-entry poll and the typed `ArchiveError::Cancelled` (FR-056); the `Io(Interrupted)` sentinel is gone.

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

- Cancellation by a callback return value (cancellation is the polled `is_cancelled`, FR-055 to FR-057)
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
WHEN ExtractRequest::with_progress(..).extract(..) is called
THEN on_entry_start is called before writing the entry,
     on_bytes_written is called once per written file with that file's byte count,
     on_entry_complete is called when the entry is finished, including an entry that failed
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

AS A developer using CreateRequest::with_progress()
I WANT progress callbacks during archive creation
SO THAT I can report file-packing progress to the user

**Acceptance criteria:**
```
GIVEN a custom ProgressCallback passed to CreateRequest::with_progress()
WHEN archive creation runs
THEN on_entry_start and on_entry_complete are called for each source file added
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | THE SYSTEM SHALL expose a `ProgressCallback` trait with methods: `on_entry_start(path, position: EntryPosition)`, `on_bytes_written(bytes)`, `on_entry_complete(path)`, `on_complete()` | must |
| FR-041 | THE SYSTEM SHALL provide a `NoopProgress` implementation that satisfies `ProgressCallback` with no runtime overhead | must |
| FR-042 | `on_complete` SHALL NOT be called if extraction fails or is partial | must |
| FR-043 | `ProgressCallback` SHALL be `Send` so it can be used across thread boundaries (Node.js, Python) | must |
| FR-044 | Format handlers SHALL accept `&mut dyn ProgressCallback` and call it consistently for each entry; callbacks SHALL fire per-entry interleaved with actual I/O (not batched before or after), and every `on_entry_start` SHALL be paired with exactly one `on_entry_complete`, also when the entry fails | must |
| FR-045 | `on_bytes_written` SHALL be called with the number of bytes written for the entry just extracted (once per written file), not a cumulative total | must |
| FR-046 | `on_entry_start` SHALL receive an `EntryPosition { current: NonZeroUsize, total: EntryTotal }` (`Copy`, `#[non_exhaustive]`, built by `new` or `at_index(0-based, total)`), where `current` is 1-based and `EntryTotal` is `Known(usize)` or `Unknown`; a stream whose count is not known up front reports `Unknown`, never 0 (#904) | must |
| FR-047 | `ListRequest::with_progress` (`list`, `list_reader`, `for_extraction`) and `VerifyRequest::with_progress` (`verify`, `verify_reader`) SHALL announce each listed or verified entry with `on_entry_start` and close it with `on_entry_complete`, and call `on_complete` once after the result was built; `on_complete` SHALL NOT fire on failure and every `on_entry_start` is still paired with an `on_entry_complete` (v0.8.0, #782, #790) | must |
| FR-048 | In listing and verification the total SHALL be `EntryTotal::Unknown` for TAR (the count is unknown until the stream ends, and stays unknown until `set_total`) and `Known` with the entry count the file table declares for ZIP and 7z (which can exceed the announced entries: 7z anti-items and entries dropped for their path are never announced); `on_bytes_written` SHALL never be called (v0.8.0, #782, #790) | must |
| FR-049 | With `IntegrityCheck::DecodeToEof` the verification events SHALL fire while each payload is decoded; without it they fire at metadata-scan speed; for 7z the entries that carry no payload are announced first, then the payloads in decode order. The events of a 7z listing fire while the file table is walked, and reading link targets (`StoredTargets::Read`) decodes afterwards without further events (v0.8.0, #790) | must |
| FR-050 | `SinkExtractRequest::with_progress` and `CreateRequest::with_progress` (`write`, `to_bytes`) SHALL follow the same contract as `ExtractRequest::with_progress` (v0.8.0, #778, #787; request types since #912) | must |
| FR-051 | WHEN an archive is created, THE SYSTEM SHALL NOT report the source root as an entry, so `total_entries` and the progress count drop by one per source directory; a file or symlink emptied by `strip_prefix` is `InvalidConfiguration` (`ConfigProblem::RemovesWholeName`) and an emptied directory is skipped; the callbacks SHALL be paired by one `EntryCompleteGuard` (`ProgressTracker::begin`) that fires `on_entry_complete` for every started entry, including a failed one, replacing the manual `on_entry_start`/`on_entry_complete` calls; TAR extraction SHALL use the same guard, so a TAR entry that fails is also closed (v0.8.0, #874, #880, #888; #904) | must |
| FR-052 | `ExtractionReport` and `CreationReport` SHALL be `#[non_exhaustive]` and SHALL carry `skipped: Skips` instead of a skipped-file counter and skip warning strings; `files_skipped()` is derived from it (#905, #906) | must |
| FR-053 | `SkipKind` SHALL be a closed `#[non_exhaustive]` enum with nine kinds (`Duplicate`, `ExtensionNotAllowed`, `NotSelected`, `StrippedAway`, `Excluded`, `Hidden`, `OverMaxFileSize`, `SymlinkUnsupported`, `Unreadable`); `Skip { kind, path, io_kind: Option<io::ErrorKind> }`; `Skips` SHALL keep a count per kind plus a sample bounded by `Skips::SAMPLE_CAP` (64) and expose `total()`, `count(kind)`, `sample()`, `is_empty()`; recording a skip SHALL fail closed with `QuotaExceeded { IntegerOverflow }` on counter overflow (`Unreadable` has no producer yet) (#906) | must |
| FR-054 | The remaining report warnings SHALL be typed `#[non_exhaustive]` enums with `Display` that keeps the former text: `ExtractionWarning::{AntiItemsSkipped { count }, BackupCleanupFailed { path, identity: BackupIdentity, io_kind, message }}` and `CreationWarning::{ZipRatioOverDefaultLimit, ZipRatioCheckFailed, DirectoryNotSynced { io_kind }}`, each with a `kind()` returning a closed `*WarningKind` whose `as_str` is the stable token used by the CLI, Python and Node; a skipped entry SHALL NOT also appear as a warning string (#906) | must |
| FR-055 | `ProgressCallback::is_cancelled(&mut self) -> bool` (default `false`) SHALL let a callback that hit an error of its own (a raising script callback, a closed channel) stop a creation: creation checks it and then returns `ArchiveError::Cancelled`, the staged output is discarded and a previous archive at the output path stays untouched; the Python adapter reports a raised exception through it (the callback's exception wins over the core `Cancelled`, `KeyboardInterrupt` included) and the Node adapter does the same for a throwing callback (`PROGRESS_CALLBACK_ERROR`); extraction, list and verify are cancelled the same way (FR-056) (#931, #973, #990) | must |
| FR-056 | `EntryCompleteGuard::try_start` SHALL poll `ProgressCallback::is_cancelled` at the start of every entry in TAR, ZIP and 7z extraction, list, verify and the creation `ProgressTracker::begin` (which now returns `Result`); a stop returns `ArchiveError::Cancelled` (error code `CANCELLED`, `FfiKind::Cancelled`), and extraction wraps it in `Partial` when files were written; `ArchiveError::is_cancelled()` SHALL see through `Partial` | must |
| FR-057 | Creation SHALL poll once more after the entry loop and before publishing the output; staged extraction SHALL poll after extraction and before the `Atomic` rename and before the `AtomicReplace` displace step; the copy of one entry polls `is_cancelled` about every 8 MiB (`CANCEL_POLL_INTERVAL` in `copy.rs`), so a stop is honoured inside a large entry; only one decoder call (a single compressed block, a 7z solid block) is not interruptible and the docs SHALL say so (#1035) | must |
| FR-058 | A binding SHALL find `Cancelled` through `PartialExtraction` as well as at top level (`merge_progress_result` in Python, `ProgressCallbackError::merge` in Node); a `Cancelled` caused by a callback exception or throw SHALL raise that exception or `PROGRESS_CALLBACK_ERROR` carrying it as the cause, with `writes` and the counters of the partial outcome; Node keeps `ABORT_ERR` for an observed `AbortSignal` and reports `CANCELLED` otherwise; Python maps an unattributed `Cancelled` to the base `ArchiveError`; a callback that raises stops the operation before the next entry, so a raise on the last entry is the success-path exception | must |

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
| `EntryPosition` / `EntryTotal` | Position passed to `on_entry_start` (#904) | `current: NonZeroUsize`; `total: Known(usize) \| Unknown` |
| `SkipKind` / `Skip` / `Skips` | Typed skip accounting in `ExtractionReport` and `CreationReport` (#906) | counts per kind, bounded sample, `total()`, `count()`, `counts()` (an iterator of every kind that occurred with its count; Python `Skips.counts` is a dict by kind), `sample()` |

### Trait Signature

```
ProgressCallback: Send
  on_entry_start(&mut self, path: &Path, position: EntryPosition)
  on_bytes_written(&mut self, bytes: u64)
  on_entry_complete(&mut self, path: &Path)
  on_complete(&mut self)  // NOT called on failure; called only on full success
```

> [!note] v0.4.0 clarification
> `on_complete` is called only on successful completion. Implementors must not
> use it for cleanup — use the `Err` return path from `extract_archive` instead.

> [!note] Internal state
> The progress callback travels through private per-format state (for example
> `ZipExtractionContext`) and the `EntryCompleteGuard` of FR-051; neither is public API.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Extraction fails on first entry | `on_entry_start` and `on_entry_complete` are called for that entry (they are always paired); `on_complete` is NOT called |
| Extraction fails after N successful entries | `on_entry_complete` called for the N successful entries and for the failing one; `on_complete` NOT called |
| 7z anti-item (a deletion marker `extract` skips) | No callbacks fire for it |
| `on_bytes_written` called with 0 bytes | Allowed; implementations must handle gracefully |
| Archive with unknown total entry count | `EntryPosition::total` is `EntryTotal::Unknown` (TAR in extraction, listing and verification); Python passes `total=None`, Node `total: null`; the CLI bar then counts entries instead of showing a length |
| Listing or verification progress for an entry | `on_bytes_written` is never called (FR-048) |
| Progress callback panics | Panic propagates as normal Rust panic; not caught by exarch |
| Creation progress for large directories | `on_entry_start` called for each file; the total is `Known` with the file count from the walk; the CLI `create` bar starts unsized and resizes from that total (`BarLength::Discover`) |
| Python progress callback raises an exception (v0.6.0, #489) | Captured, not silently swallowed (previously discarded via `let _ = ...`); the `ProgressCallback` contract has no cancellation signal, so before #981 the operation ran to completion; since #981 `is_cancelled` stops it (FR-056) and the callback's exception propagates to the caller carrying `files_extracted`/`files_added`, `bytes_written`, and a `progress_callback_error = True` marker attribute — see [[006-python-bindings/spec]] |
| Python or Node.js progress callback raises during an in-memory list, verify or extract (v0.8.0, #784, #783, #790) | Handled like the path-based calls: if the operation failed, its error is primary with the callback's exception chained (`__cause__` / `cause`); if it succeeded, the result is discarded and the callback's exception is raised (Python: `progress_callback_error = True`; Node: `code` `PROGRESS_CALLBACK_ERROR`); an in-memory extraction additionally carries `writes: discarded` and no counters — see [[006-python-bindings/spec]] and [[007-node-bindings/spec]] |
| Node.js progress callback throws an `Error`/object (v0.6.0, #465) | Captured via `call_async_catch` instead of routing through `napi_fatal_exception` (which previously crashed the process uncatchably even inside `try`/`catch`); rejects the returned Promise instead — see [[007-node-bindings/spec]] |
| Node.js progress callback throws a bare primitive (string/number/boolean) (v0.6.0, #473) | Also captured, not just `Error`/object throws — closed a separate napi-rs `napi_create_reference()` escalation gap via a JS shim wrapping the callback; does not cover `createArchiveWithProgressSync`, which dispatches unawaited and was never affected by this class of bug |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `on_complete` not called on failure | Regression test (issue #170, fixed in v0.4.0) |
| SC-002 | Progress overhead vs no-progress | < 5% throughput penalty (measured in bench) |
| SC-003 | All format handlers (TAR, ZIP, 7z) call progress callbacks per-entry | Fixed in v0.4.0 (#170, #191) |
| SC-004 | Node.js creation progress parity with extraction | `createArchiveWithProgress` added (v0.6.0, #455; the `createArchiveWithProgressSync` variant was removed in #953, since a synchronous creation cannot be cancelled by a throwing callback), reusing the core creation request (`CreateRequest::with_progress` since #912) and the existing `NodeProgressAdapter`; JS integration tests cover the per-entry callback shape and `progress=null`/omitted paths (#456) |

## 8. Agent Boundaries

### Always (without asking)
- Call `on_entry_start` before writing any bytes for an entry
- Call `on_entry_complete` after writing all bytes for an entry
- Call `on_complete` only on full success, never on error
- Open every entry through `EntryCompleteGuard` so start and complete stay paired and cancellation is polled

### Ask First
- Adding new methods to `ProgressCallback` (trait breaking change)
- Adding a variant to `SkipKind` (closed enum: every consumer mirrors it and has an `ALL` drift test)
- Changing how cancellation is polled (`is_cancelled`, FR-055 to FR-057)

### Never
- Call `on_complete` on partial or failed extraction
- Depend on a specific `ProgressCallback` implementation inside `exarch-core`
- Remove `Send` bound from `ProgressCallback`

## 9. Open Questions

- [RESOLVED: cancellation is `ProgressCallback::is_cancelled`, polled at entry boundaries (FR-055 to FR-057, #973, #990); `on_entry_start` still returns nothing.]
- [RESOLVED: `on_bytes_written` receives the byte count of one finished file (FR-045); the CLI sums it for the bar message and advances per entry.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — format handlers that call progress callbacks
- [[005-cli/spec]] — indicatif-based `ProgressCallback` implementation
- [[021-create-staging-and-output-policy/spec]] — creation skips (`Excluded`, `Hidden`, `OverMaxFileSize`, `SymlinkUnsupported`)
- [[006-python-bindings/spec]] — `PyProgressAdapter` and GIL interaction; callback exception propagation
- [[007-node-bindings/spec]] — `NodeProgressAdapter`, `createArchiveWithProgress`, primitive-throw hardening
- [[019-verify-and-list-model/spec]] — listing and verification passes that report progress
- [[020-reader-sink-and-in-memory-api/spec]] — reader, sink and writer variants of the progress-reporting calls
- [[001-exarch-system/spec]] — original monolithic spec (archived)
