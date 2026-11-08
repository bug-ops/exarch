---
aliases:
  - Node.js Bindings Spec
  - napi-rs Bindings Spec
tags:
  - sdd
  - spec
  - nodejs
  - ffi
  - rust
created: 2026-05-20
updated: 2026-11-06
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Node.js Bindings

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> `ExarchError` union, `IoKind`, `SinkOptions`, entry unions, number-to-limit boundary, `total: null`, skipped summary, injective path rendering and staged `createArchive`. See FR-106 to FR-113; rows that conflict (FR-090, FR-101) are rewritten in place.

> [!info] Metadata
> **Subsystem**: exarch-node
> **MSRV**: Rust 1.99.1
> **Build**: napi-rs 3.x + tokio runtime
> **Source**: extracted from [[001-exarch-system/spec]]

> [!note] Batch #1008 amendments
> Builder methods `set*` become `with*` (FR-120); dispositions use `action`/`kind` (FR-121); `path`, `leftoverPath` and warning `reason` (FR-122, FR-123); size clamp 2^53-1 (FR-099). All builder names in this spec use the `with*` form.

> [!note] Batch #981 amendments
> `withExistingFiles('skip' | 'overwrite' | 'refuse')` replaces `withSkipDuplicates` (FR-115); `withAllowedExtensions([])` throws and `null` clears (FR-116); `Cancelled` and the new errors are mapped (FR-117); `withStaging` replaces `withAtomic` (FR-118); typed warnings and compression-level errors (FR-119); selection on `SecurityConfig` ([[022-extract-entry-selection/spec]] FR-104).

## 1. Overview

### Problem Statement

Node.js developers building CI/CD tools, file processing services, or
developer tooling need safe archive operations that do not block the event
loop. Wrapping `exarch-core` via napi-rs gives Node.js callers the same
security guarantees as the Rust API, exposed as async Promises running on
the libuv thread pool.

### Goal

Expose `exarch-core` operations as async Promise-based functions in a native
Node.js addon built with napi-rs, with path validation at the JS boundary,
named JavaScript error types, and TypeScript type definitions.

### Out of Scope

- Streaming Node.js readable/writable interfaces
- Electron or browser support (Node.js native addon only)
- CommonJS-only distribution (ESM and CJS both supported by napi-rs)

## 2. User Stories

### US-001: Async Archive Extraction

AS A Node.js developer
I WANT to `await extractArchive(archivePath, outputDir)` without blocking the event loop
SO THAT my server can handle other requests while an archive is being extracted

**Acceptance criteria:**
```
GIVEN a valid archive path and output directory as strings
WHEN await extractArchive(archivePath, outputDir) is called
THEN extraction runs on the libuv thread pool, files are extracted, and an ExtractionReport is resolved
```

### US-002: Path Validation at JS Boundary

AS A Node.js developer
I WANT invalid paths to be rejected synchronously before a Promise is created
SO THAT I receive a clear JS Error for obvious mistakes without awaiting

**Acceptance criteria:**
```
GIVEN a path string containing null bytes
WHEN any exarch function is called with that path
THEN a JavaScript Error is thrown synchronously before the Promise is created
```

```
GIVEN a path string exceeding 4096 bytes
WHEN any exarch function is called with that path
THEN a JavaScript Error is thrown synchronously
```

### US-003: Named JavaScript Error Types

AS A Node.js developer
I WANT Rust ArchiveError variants to produce JS Error objects with typed properties
SO THAT I can differentiate errors in a catch block without parsing message text

**Acceptance criteria:**
```
GIVEN an archive with a path traversal entry
WHEN extractArchive() rejects
THEN the rejected Error has code === "PATH_TRAVERSAL" and a message holding the description only
```

### US-004: TypeScript Definitions

AS A TypeScript developer
I WANT `.d.ts` type definitions for all functions and classes
SO THAT I have type safety and IDE autocomplete

**Acceptance criteria:**
```
GIVEN the installed npm package
WHEN imported in a TypeScript project
THEN all functions, classes, and return types have correct TypeScript signatures
```

### US-005: Custom Security Config

AS A Node.js developer
I WANT to instantiate a SecurityConfig class and pass it to archive functions
SO THAT I can customize extraction limits in JavaScript

**Acceptance criteria:**
```
GIVEN new SecurityConfig().withMaxFileSize(200 * 1024 * 1024).withAllowSymlinks(false)
WHEN passed to extractArchive()
THEN extraction respects those settings
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-080 | THE SYSTEM SHALL expose async Node.js functions returning Promises: `extractArchive`, `extractArchiveWithProgress`, `createArchive`, `createArchiveWithProgress`, `listArchive`, `verifyArchive` (`createArchiveWithProgress` added v0.6.0, #455, via the shared `NodeProgressAdapter`; the `createArchiveWithProgressSync` variant was removed in #953 because a callback that throws cannot cancel a synchronous creation) | must |
| FR-081 | ALL async operations SHALL run on the libuv thread pool, not the main event loop thread | must |
| FR-082 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL throw a synchronous JavaScript Error before spawning a thread | must |
| FR-083 | Every rejected Promise and synchronous throw SHALL be an `Error` (`ExarchError` in `index.d.ts`) whose `message` is the human-readable description only and whose machine-readable data is in typed properties built from `exarch_core::ArchiveError::into_ffi_message()` (BREAKING in v0.8.0, #758, #760, #768): `code` (`ErrorCode`, the stable upper-snake core code, or `PROGRESS_CALLBACK_ERROR`), `relaxableBy?` (`PolicySetting`), `writes?` (`PartialWrites`: `'kept'`, `'rolled_back'`, `'discarded'`), and, when `writes === 'kept'`, `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings`; when `PartialExtraction` wraps an inner error, `code` is the inner error's code. The types `ErrorCode`, `PolicySetting`, `PartialWrites` and `ExarchError` (a union discriminated on `writes`, including `ExarchNativeError` for binding-raised errors whose `code` is napi's status string) are exported | must |
| FR-084 | `SecurityConfig` and `CreationConfig` SHALL be exposed as JavaScript classes with fluent builder methods; `SecurityConfig` SHALL expose `allowSolidArchives` getter consistent with `allowSymlinks`, `allowHardlinks`, `allowAbsolutePaths`, `allowWorldWritable` | must |
| FR-085 | `ExtractionReport`, `CreationReport`, `ArchiveManifest`, and `VerificationReport` SHALL be exposed as JavaScript objects with typed fields | must |
| FR-088 | `ExtractionOptions` SHALL be exposed as a JavaScript class with builder methods `withStaging` and `withExistingFiles` (FR-115, FR-118; they replaced `withAtomic` and `withSkipDuplicates`); both `extractArchive` and `extractArchiveWithProgress` SHALL accept an optional `options` parameter | must |
| FR-089 | ALL async operations SHALL wrap the core call with `catch_unwind` inside `spawn_blocking`; panics in `exarch-core` SHALL be converted to JavaScript errors and SHALL NOT abort the Node.js process | must |
| FR-090 | `extractArchiveWithProgress(archivePath, outputDir, config?, options?, progress?)` SHALL accept an optional `ThreadsafeFunction` callback with signature `(path: string, total: number \| null, current: number, bytesWritten: number) => void` (`total` is `null` while the count is unknown, FR-110); numeric callback arguments are `number` (not `bigint`) | must |
| FR-086 | napi-rs SHALL generate TypeScript `.d.ts` files for all exported functions and classes | must |
| FR-087 | ALL path arguments SHALL accept `string` type in JavaScript | must |
| FR-091 | `SecurityConfig.withAllowSymlinks`/`withAllowHardlinks`/`withAllowAbsolutePaths`/`withAllowWorldWritable`/`withAllowSolidArchives`/`withPreservePermissions`, `CreationConfig.withPreservePermissions`/`withFollowSymlinks`/`withIncludeHidden`, and the former `ExtractionOptions.withSkipDuplicates`/`withAtomic` (now `withExistingFiles`/`withStaging`, enum arguments) SHALL take a mandatory `boolean` argument, not `Option<bool>` resolved via `.unwrap_or(true)`; omitting the argument, or passing explicit `undefined`/`null`, SHALL be a compile-time TypeScript error / runtime napi error rather than silently flipping the flag to the permissive `true` state (v0.6.0, #442, BREAKING) | must |
| FR-092 | WHEN a `PartialExtraction` error is converted to a JS error, THE SYSTEM SHALL set `writes` and, only while the written files remain (`'kept'`), the properties `filesExtracted`, `bytesWritten`, `filesSkipped` and `warnings` (typed objects, FR-119); an atomic rollback sets only `writes: 'rolled_back'` and an in-memory extraction that dropped its entries only `writes: 'discarded'`. Before v0.8.0 these were appended to the message as ` \| writes=kept, filesExtracted=N, ...` (v0.6.0, #508; v0.7.0, #747; v0.8.0, #760, #768, #800, #808) | must |
| FR-093 | WHEN a progress callback throws (an `Error`/object, or a bare primitive) during `extractArchiveWithProgress` or `createArchiveWithProgress`, THE SYSTEM SHALL capture it (via `call_async_catch` plus a JS shim that pre-empts napi-rs's primitive-throw escalation) and reject the returned Promise instead of crashing the process with `napi_fatal_exception`; the synchronous creation variant that would have deadlocked the blocked event loop was removed in #953 (v0.6.0, #465, #473) | must |
| FR-094 | ALL path-carrying `ArchiveError` variants SHALL be redacted for release-build error messages via the shared core redaction helpers (the public `sanitize_path_for_error`, `sanitize_io_error_for_error` and `format_entry_path_for_error`, re-exported at the `exarch_core` root), matching the Python binding's policy (archive-relative paths never redacted; host-derived paths redacted to filename-only or `ErrorKind` description) (v0.6.0, #453, #463) | must |
| FR-095 | `verifyArchive(archivePath, config?, options?)` (and `verifyArchiveSync`) SHALL accept a `VerificationOptions` class; `withIntegrityCheck(budget?)` decodes the payload to the decoder's EOF (default budget 500 MiB, independent of `maxTotalSize`; error for a zero or negative budget), otherwise `integrityStatus` is `'SKIPPED'` (v0.7.0, #670) | must |
| FR-096 | `VerificationReport` SHALL expose `status`, `integrityStatus`, `integrityGaps?` (absent unless the check ran: `counts: UnverifiedCount[]`, `entries: UnverifiedEntry[]`, `omitted`), `securityStatus`, `issues`, `totalEntries`, `suspiciousEntries`, `totalSize` and `format`; report enum fields are typed string unions in `index.d.ts` (`VerificationStatus`, `CheckStatus`, `IntegrityStatus`, `IssueSeverity`, `IssueCategory`, `UnverifiedReason`, `ManifestEntryType`, `ArchiveType`, `ZipConsistencyPolicy`) (v0.7.0, #624, #672, #684) | must |
| FR-097 | `SecurityConfig` SHALL expose `withParallelDecodeMemory(size?)` (`null`/omitted decodes on one thread; default 128 MiB, 1 GiB for `permissive()`; error for a non-positive size) with a `parallelDecodeMemory` getter, and `withZipConsistency('enforce' \| 'ignore')` (default `'enforce'`) with a `zipConsistency` getter (v0.7.0, #671, #688) | must |
| FR-098 | A `SECURITY_VIOLATION` that a `SecurityConfig` setting relaxes SHALL carry the property `relaxableBy` with `<id>` one of `symlinks`, `hardlinks`, `solid_archives`, `banned_components`, `max_path_depth`, `windows_reserved_names`, `max_tar_metadata_bytes` (`PolicySetting`); the property is absent when no setting relaxes the refusal and a violation reason cannot forge it. The `[relaxableBy=<id>]` message token of v0.7.0 no longer exists (v0.7.0, #741, #757; v0.8.0, #760, #768) | must |
| FR-099 | Report size, count and duration getters and the progress tuple SHALL clamp values above 2^53-1 (`Number.MAX_SAFE_INTEGER`) to 2^53-1 instead of wrapping or losing precision (v0.7.0, #583, #697; clamp lowered from `i64::MAX` in #1012) | must |
| FR-100 | A progress callback that throws SHALL surface as the rejection or throw with `code` `PROGRESS_CALLBACK_ERROR`, the exception as `cause` (the `\| progressCallbackError` message marker is removed), and, when the operation itself succeeded, the counters: `filesExtracted`/`bytesWritten`/`filesSkipped`/`warnings` for an extraction (`writes: 'kept'`), `filesAdded` and `bytesWritten` for a creation, `writes: 'discarded'` for an in-memory extraction; if the operation failed, the core error stays primary with the callback's exception as `cause` (v0.8.0, #760, #768, #783, #790) | must |
| FR-101 | THE SYSTEM SHALL expose in-memory functions on `Uint8Array` input: `listArchiveBytes(data, config?, format?)`, `verifyArchiveBytes(data, config?, options?, format?)`, `extractArchiveToMemory(data, config?, options?, maxBytes?, pathModel?, format?)` (`options` is a `SinkOptions`, FR-107) resolving `MemoryExtraction { report, entries }` of `StoredMemoryEntry` unions (FR-108), and `createArchiveToBytes(sources, format, config?)` resolving `CreatedArchive { data, report }`, each with a `Sync` counterpart; `listArchiveBytesWithProgress`, `verifyArchiveBytesWithProgress` and `extractArchiveToMemoryWithProgress` take the same `(err, [path, total, current, bytesWritten])` callback as the path-based progress functions. `data` is copied before the call returns; `maxBytes` must be a positive whole number (default the config's `maxTotalSize`); `pathModel` is `'host'` or `'portable'`; `atomic` is unsupported; `format` is detected from the leading bytes when omitted; `'SevenZ'` cannot be created (`INVALID_CONFIGURATION`); a `MemoryEntry.data` is a plain `Uint8Array`, not a `Buffer` ([[020-reader-sink-and-in-memory-api/spec]]; v0.8.0, #776, #787, #790) | must |
| FR-102 | Quota errors for a single oversized file SHALL use the core wording `single file size` (v0.8.0, #760, #768) | should |
| FR-103 | THE SYSTEM SHALL expose `extractArchiveToCallback(data, onEntry, config?, options?, pathModel?, format?, signal?)` (Promise) and `extractArchiveToCallbackSync`, delivering each verified entry to `onEntry` (which may return a promise in the async form; the sync form fails with a `TypeError` for a promise) through `extract_reader_to_callback`; `data` MAY be an `AsyncIterable<Uint8Array>` (TAR family) in the async in-memory functions, read on a worker thread and closed with `return()` however the call ends; a throw or rejection of `onEntry` rejects with `ENTRY_CALLBACK_ERROR`, an iterable that throws with `STREAM_ERROR`, and the abort reason is kept when the abort is raised from `onEntry`; `index.d.ts` uses `AsyncIterable` and needs the `es2018` lib (v0.8.0, #842, #860, #884) | must |
| FR-104 | The seven async in-memory functions that take an `AsyncIterable` SHALL accept an optional trailing `signal` (`AbortSignalLike`); aborting rejects with `ABORT_ERR` and frees the blocking worker, the abort being noticed when the job starts, while it waits for JavaScript, at every read of a `Uint8Array` archive and at each progress callback; a pending `onEntry` call is abandoned, not cancelled; a `signal` that is not an `AbortSignal` throws a `TypeError` synchronously (v0.8.0, #848, #856) | must |
| FR-105 | THE SYSTEM SHALL expose `extractArchiveToMemoryWithProgressSync`, `listArchiveBytesWithProgressSync` and `verifyArchiveBytesWithProgressSync`, and every error SHALL carry `subCode` and `setting` as properties with typings when core supplies them (v0.8.0, #842, #865, #870) | should |
| FR-106 | `ExarchError` SHALL be a discriminated union that pairs each `code` with its properties (`ExarchCoreError` = every shape but `ExarchNativeError`; `INVALID_ARCHIVE` with optional `InvalidArchiveSubCode`, `SECURITY_VIOLATION` with a required `SecurityViolationSubCode` and optional `relaxableBy`, `QUOTA_EXCEEDED` and `ZIP_BOMB` with a required `QuotaSubCode` or `ZipBombSubCode`, `INVALID_CONFIGURATION` with `setting`, `IO_ERROR` with a required `ioKind: IoKind`), crossed with `writes`; `IoKind` is a stable string enum of 24 `io::ErrorKind` values plus `Other`; mirror enums have reverse drift tests (`mirror_maps_to_core!`) and `InvalidArchiveSubCode` includes `TAR_READER` and `SEVENZ_READER` (#924, #920, #918, #930, #896) | must |
| FR-107 | The in-memory and callback functions SHALL take a `SinkOptions` class (`withExistingFiles`, `existingFiles`, `withDecodeReuse(mode, limit?)`, `decodeReuse`, `decodeReuseLimit`) instead of `ExtractionOptions` (passing `ExtractionOptions` throws `InvalidArg` synchronously; `atomic` cannot be requested) (#926) | must |
| FR-108 | `MemoryEntry` SHALL be a union discriminated by `kind` (`MemoryFileEntry`, `MemoryDirectoryEntry`, `MemorySymlinkEntry`, `MemoryHardlinkEntry`) and `MemoryExtraction.entries` SHALL be `StoredMemoryEntry[]` (no hardlink); `listArchive*` entries SHALL be `ArchiveEntry` = `ManifestFileEntry \| ManifestDirectoryEntry \| ManifestSymlinkEntry \| ManifestHardlinkEntry` discriminated by `entryType` with `size` only on files, `mode` the raw archive mode and links carrying `target: LinkTarget` (`recorded { path }`, `missing`, `unread`, `unreadable`, `oversized { bytes }`); `symlinkTarget` and `hardlinkTarget` are removed (#923, #910) | must |
| FR-109 | `SecurityConfig` count, depth and size setters (and `CreationConfig.withMaxFileSize`) SHALL take a JS number through core `positive_from_f64`: negative, fractional, non-finite, zero and above 2^53-1 are `INVALID_CONFIGURATION` with `setting`; `maxFileCount` is `number \| null` (null is unbounded); `withParallelDecodeMemory`, `withIntegrityCheck` and `addExcludePattern` throw `INVALID_CONFIGURATION` with `parallel_decode_memory`, `decompression_budget` and `exclude_pattern`; the `maxSolidBlockMemory` getter is `number \| null` and its setter throws `INVALID_CONFIGURATION` while solid archives are refused; every path argument goes through `BoundaryPath::parse` and only the parsed value reaches core (#917, #921, #927, #911) | must |
| FR-110 | The progress callback tuple SHALL be `ProgressArgs = [path, total: number \| null, current, bytesWritten]` with `total` `null` while the count is unknown; reports SHALL carry `skipped: SkippedSummary { counts: { kind, count }[], sample: SkippedEntry[] }` (kind typed `SkipKind`, `ioKind?: IoKind`), `filesSkipped` is the total over all reasons, `warnings` are typed objects (FR-119), and the error object of a kept partial extraction carries `skipped` as well as `filesSkipped`; the tuple is the exported alias `ProgressArgs` in every progress-taking function, listing and verification included (#904, #906) | must |
| FR-111 | `VerificationIssue` SHALL carry `code`, `subCode`, `relaxableBy`, `setting` and `ioKind` from the core finding (typed as the generated fields intersected with `ExarchErrorCodeDetail \| HeuristicIssueDetail`); `context` is removed; `mode?: number` carries the raw mode of an invalid-permissions finding (#899) | must |
| FR-112 | Listing SHALL refuse a non-UTF-8 entry name or link target with `INVALID_ARCHIVE` (`ENTRY_NAME`) through core `ArchiveEntry::utf8_path()`; verify issue paths, integrity gap paths, skip samples and progress paths SHALL use an injective `path_text` rendering (core `exarch_core::path_text`: `\` is written `\x5C`, each invalid Unix byte `\xNN`, each unpaired UTF-16 unit `\uNNNN`), so a literal name `a\xFFb` and a name with the byte 0xFF stay distinct; a caller cannot recover the original bytes (no `pathBytes` field); the `INVALID_ARCHIVE` error of a refused listing carries the same rendering as `nonUtf8EntryPath` (#925) | must |
| FR-113 | `createArchive*` SHALL take an optional trailing `CreateOptions { format?: CreatableFormat, overwrite?: boolean, durability?: Durability }` (`createArchiveWithProgress` after the progress argument; `CreatableFormat` is a napi string enum without `'SevenZ'`, so `'SevenZ'` is a TypeScript compile error and a napi `InvalidArg` refusal; `Durability` is `'synced' | 'unsynced'`, see [[021-create-staging-and-output-policy/spec]] FR-027): the default replaces an existing output atomically (`OutputFile::replace`), `overwrite: false` maps to `create_new` and rejects with `OUTPUT_EXISTS`, `format` maps to `OutputFile::with_format` and `'SevenZ'` is refused; a failed creation leaves any previous archive untouched (see [[021-create-staging-and-output-policy/spec]]); a progress callback that throws cancels the creation (nothing is written, `PROGRESS_CALLBACK_ERROR`, typed `ExarchErrorReadCallback`/`ExarchErrorCreationCallback`); `addExcludePattern` parses with core `ExcludePattern::try_from` (#912, #915, #931, #916) | must |
| FR-114 | `createArchiveToBytes` and `createArchiveToBytesSync` SHALL take `format: CreatableFormat`; the Node `ConfigSetting` mirror SHALL include `'durability'`, and a test SHALL pin that the napi `CreatableFormat` and `Durability` values equal the core `NAMES` | must |
| FR-115 | `ExtractionOptions` and `SinkOptions` SHALL take `existingFiles` as the napi string enum `ExistingFiles` (`'skip' | 'overwrite' | 'refuse'`, default `'skip'`) through `withExistingFiles` and the `existingFiles` getter (`withSkipDuplicates` and `skipDuplicates` are removed; the `SinkOptions` setters are `with*`); `refuse` surfaces a pre-existing file as `OUTPUT_EXISTS` with `conflicts: string[]` of entry names, leaves it untouched and counts an in-archive duplicate as skipped | must |
| FR-116 | `SecurityConfig` `allowedExtensions` SHALL be `string[] | null` (`null` for Any); `withAllowedExtensions(null)` SHALL clear it, `withAllowedExtensions([])` SHALL throw `INVALID_CONFIGURATION` with setting `allowed_extension` and problem `Empty`, and `undefined` is a napi `InvalidArg`, not a clear; `withBannedComponents(string[])` and `CreationConfig.withExcludePatterns(string[])` validate the whole list before replacing it and keep their meaning for `[]` (an empty ban or exclude list is not fail-open) | must |
| FR-117 | The binding SHALL add `ErrorCode` `CANCELLED`, find `Cancelled` through `PartialExtraction`, keep `ABORT_ERR` for an `AbortSignal` stop and `PROGRESS_CALLBACK_ERROR` (the throw as `cause`, with `writes` and counters) for a throwing callback, which now stops list, verify, extraction and creation at the next entry; it SHALL map `DestinationOccupied` (`OUTPUT_EXISTS`) and `OutputReservationLeft` with host paths redacted in release builds; its `IoKind` mirror SHALL derive from core `IoKind` (#989) | must |
| FR-118 | `ExtractionOptions.withStaging` and the `staging` getter SHALL replace `withAtomic` and `atomic`, with the napi enum `Staging` (`'in_place' | 'atomic' | 'atomic_replace'`, values equal to core `as_str`); `SinkOptions` has no staging; `atomic` into a non-empty directory is `OUTPUT_EXISTS` with the destination untouched, `atomic_replace` swaps a populated destination and refuses a protected one (`protectedPath`: `filesystem_root`, `archive_ancestor`, `working_directory`); error objects SHALL carry `restore` (`not_needed`, `restored`, `failed`), `backupPath` (when `failed`) and `leftoverPath` for `ReplaceFailed` (`leftoverPath` also for `OutputReservationLeft`), `conflicts` for `DestinationOccupied`, and `collision { name, first, second }` for `EntryNameCollision` (setting `source_paths`), all host paths through `sanitize_path_for_error`; `ExtractionOptions` (path) has no `decodeReuse` | must |
| FR-119 | Report and error `warnings` SHALL be discriminated objects (`kind` equal to the core `as_str`, `message`, plus per-kind fields) instead of strings; a fractional, negative, non-finite or huge compression level SHALL be `INVALID_COMPRESSION_LEVEL` (it was napi `InvalidArg`); `SOURCE_NOT_ACCESSIBLE` SHALL carry `errno`, `strerror` and `path` | must |
| FR-120 | Every builder method of `SecurityConfig` and `CreationConfig` SHALL be named `with*`, matching the core builders and the Python binding; the 26 former `set*` methods are renamed with no alias (breaking before v1.0.0), and the getters keep their names (#1010) | must |
| FR-121 | A `Disposition` SHALL be discriminated by `action` (`'extract'` with `landing`, `'skip'` with `kind: SkipKind`), replacing the former `kind: 'extract' \| 'skip'` and `reason`; the values derive from core `DispositionKind::as_str` and `SkipKind`, and a parity test checks that every enumerable token of the core `ALL` tables (`ErrorCode`, sub-codes, `SkipKind`, `IoKind`, `DispositionKind`, `RestoreKind`, `ExtractionWarningKind`, `CreationWarningKind`) appears in the Node stub (#1011, #1010) | must |
| FR-122 | `SOURCE_NOT_FOUND` SHALL carry `path`, and `OUTPUT_EXISTS` (including a refused `DestinationOccupied`) SHALL carry `path`, both redacted like an error message; `leftoverPath` SHALL name a staging directory or empty output reservation that a failure left on disk, on every error that core reports one for, including a progress-callback cancellation (`PROGRESS_CALLBACK_ERROR` through `CallbackCancelled`/`CreationCancelled`) (#995, #1009) | must |
| FR-123 | The `backup_cleanup_failed` extraction warning SHALL carry `reason`, the removal failure text redacted like an I/O error message; the progress tuple's `bytesWritten` slot stays `0` (only `on_entry_start` dispatches and no byte of that entry is written yet), which `index.d.ts` documents (#1012) | should |
| FR-124 | `SecurityConfig` SHALL carry the entry selection of [[022-extract-entry-selection/spec]] FR-104 (`addIncludePattern`, `withIncludePatterns`, `addExcludePattern`, `withExcludePatterns`, `withStripComponents(number \| null)`, `withFlatten(boolean)`); patterns use the glob grammar of [[023-entry-selection-glob-patterns/spec]] and a refused pattern is `INVALID_CONFIGURATION` with `setting` `entry_include` or `entry_exclude`; an include that matched no entry rejects with `INVALID_CONFIGURATION` carrying `unmatchedPatterns: string[]`; the binding adds no matching logic | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | All I/O runs on libuv thread pool; main event loop is never blocked |
| NFR-002 | Correctness | Path boundary validation is synchronous — errors thrown before Promise creation |
| NFR-003 | Compatibility | napi-rs 3.x; Node.js LTS version range [NEEDS CLARIFICATION: minimum Node.js version] |
| NFR-004 | Testability | Node.js tests run via `npm test` — excluded from `cargo nextest` |
| NFR-005 | Correctness | All security logic stays in `exarch-core`; Node.js crate contains only type mapping and boundary validation |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SecurityConfig` (JS class) | JavaScript class wrapping Rust `SecurityConfig` | Fluent builder: `withMaxFileSize()`, `withMaxTotalSize()`, `withAllowSymlinks()`, `withZipConsistency()`, `withParallelDecodeMemory()`, etc. |
| `CreationConfig` (JS class) | JavaScript class wrapping Rust `CreationConfig` | Fluent builder: `withCompressionLevel()`, `withFollowSymlinks()`, etc. |
| `ExtractionReport` (JS object) | Result of extraction | `filesExtracted`, `directoriesCreated`, `symlinksCreated`, `bytesWritten`, `durationMs`, `filesSkipped`, `skipped`, `warnings` |
| `CreationReport` (JS object) | Result of creation | `filesAdded`, `directoriesAdded`, `symlinksAdded`, `bytesWritten`, `bytesCompressed`, `durationMs`, `filesSkipped`, `skipped`, `warnings` |
| `ArchiveManifest` (JS object) | Archive listing result | `totalEntries`, `totalSize`, `format`, `entries` |
| `VerificationReport` (JS object) | Verification result | `status`, `integrityStatus`, `integrityGaps`, `securityStatus`, `issues`, `totalEntries`, `suspiciousEntries`, `totalSize`, `format` |
| `MemoryExtraction` / `MemoryEntry` / `CreatedArchive` (JS objects) | Results of the in-memory functions (v0.8.0; unions since #923) | `report`, `entries: StoredMemoryEntry[]` / `kind`-discriminated `MemoryFileEntry`, `MemoryDirectoryEntry`, `MemorySymlinkEntry`, `MemoryHardlinkEntry` / `data`, `report` |
| `ArchiveEntry` (TS union) | Listing entries (#923, #910) | `ManifestFileEntry \| ManifestDirectoryEntry \| ManifestSymlinkEntry \| ManifestHardlinkEntry` by `entryType`; `target: LinkTarget` on links |
| `SinkOptions` (JS class) | Options of the in-memory and callback functions (#926) | `withExistingFiles`, `existingFiles`, `withDecodeReuse`, `decodeReuse`, `decodeReuseLimit` |
| `SkippedSummary` / `SkippedEntry` | Typed skips in reports (#906) | `counts`, `sample`; `kind: SkipKind`, `path`, `ioKind?` |
| `ExarchError` (TS type) | Union of the shapes a rejection or throw can have (v0.8.0; per-`code` pairing since #924) | `ExarchCoreError` (code-paired details) crossed with `writes`, plus `ExarchNativeError`; `relaxableBy?`, `cause?`, `ioKind`, `subCode`, `setting` |
| `VerificationOptions` (JS class) | Options for `verifyArchive` (v0.7.0, #670) | `withIntegrityCheck(budget?)`, `integrityCheck`, `decompressionBudget` |

### TypeScript API Surface

```typescript
// All functions are async (Promise-based)
function extractArchive(
    archivePath: string,
    outputDir: string,
    config?: SecurityConfig,
    options?: ExtractionOptions
): Promise<ExtractionReport>

function extractArchiveWithProgress(
    archivePath: string,
    outputDir: string,
    config?: SecurityConfig,
    options?: ExtractionOptions,
    progress?: (err: Error | null, arg: [string, number | null, number, number]) => void
): Promise<ExtractionReport>

function createArchive(
    outputPath: string,
    sources: string[],
    config?: CreationConfig,
    options?: CreateOptions   // { format?, overwrite?, durability? }, FR-113
): Promise<CreationReport>

function listArchive(
    archivePath: string,
    config?: SecurityConfig
): Promise<ArchiveManifest>

function verifyArchive(
    archivePath: string,
    config?: SecurityConfig,
    options?: VerificationOptions
): Promise<VerificationReport>

// In-memory (v0.8.0); each also exists as <name>Sync, and the progress variants
// listArchiveBytesWithProgress, verifyArchiveBytesWithProgress and
// extractArchiveToMemoryWithProgress take a trailing progress callback
function listArchiveBytes(data: Uint8Array, config?: SecurityConfig, format?: ArchiveType): Promise<ArchiveManifest>
function verifyArchiveBytes(data: Uint8Array, config?: SecurityConfig, options?: VerificationOptions, format?: ArchiveType): Promise<VerificationReport>
function extractArchiveToMemory(data: Uint8Array, config?: SecurityConfig, options?: SinkOptions, maxBytes?: number, pathModel?: PathModel, format?: ArchiveType): Promise<MemoryExtraction>
function createArchiveToBytes(sources: string[], format: CreatableFormat, config?: CreationConfig): Promise<CreatedArchive>

class SecurityConfig {
    withMaxFileSize(size: number): this
    withMaxTotalSize(size: number): this
    withMaxCompressionRatio(ratio: number): this
    withMaxFileCount(count: number): this
    withMaxPathDepth(depth: number): this
    withAllowSymlinks(allow: boolean): this
    withAllowHardlinks(allow: boolean): this
    withAllowSolidArchives(allow: boolean): this
    withZipConsistency(policy: ZipConsistencyPolicy): this
    withParallelDecodeMemory(size?: number | null): this
    withMaxSolidBlockMemory(size: number): this  // INVALID_CONFIGURATION while solid archives are refused
    // Selection (specs 022, 023): addIncludePattern, withIncludePatterns, addExcludePattern,
    // withExcludePatterns, withStripComponents(count | null), withFlatten(flatten)
    // Getters
    get allowSymlinks(): boolean
    get allowHardlinks(): boolean
    get allowAbsolutePaths(): boolean
    get allowWorldWritable(): boolean
    get allowSolidArchives(): boolean
    get zipConsistency(): ZipConsistencyPolicy
    get parallelDecodeMemory(): number | null
    get maxSolidBlockMemory(): number | null
}

class SinkOptions {
    withExistingFiles(existingFiles: 'skip' | 'overwrite' | 'refuse'): this
    get existingFiles(): 'skip' | 'overwrite' | 'refuse'
}

class VerificationOptions {
    withIntegrityCheck(budget?: number | null): this
    get integrityCheck(): boolean
    get decompressionBudget(): number | null
}

class CreationConfig {
    withCompressionLevel(level: number): this  // non-integer or out-of-range input is INVALID_COMPRESSION_LEVEL
    withFollowSymlinks(follow: boolean): this
    withIncludeHidden(include: boolean): this
    addExcludePattern(pattern: string): this
    withExcludePatterns(patterns: string[]): this
    withMaxFileSize(size: number | null): this  // null = no limit; 0 is INVALID_CONFIGURATION
}

class ExtractionOptions {
    withStaging(staging: 'in_place' | 'atomic' | 'atomic_replace'): this
    withExistingFiles(existingFiles: 'skip' | 'overwrite' | 'refuse'): this
    get staging(): Staging
    get existingFiles(): ExistingFiles
}
```

> [!note] v0.5.0: `ExtractionOptions` and `extractArchiveWithProgress`
> Both functions now accept an optional `ExtractionOptions` parameter. The progress callback
> arguments (`total`, `current`, `bytesWritten`) are `number` (NAPI-RS maps `i64` to `number`),
> not `bigint`. `index.d.ts` is committed to the repository so TypeScript consumers have correct
> types without building from source.

> [!note] Unreleased (v0.6.0): boolean setters now require an explicit argument (#442, BREAKING)
> `SecurityConfig.withAllowSymlinks`/`withAllowHardlinks`/`withAllowAbsolutePaths`/
> `withAllowWorldWritable`/`withAllowSolidArchives`/`withPreservePermissions`,
> `CreationConfig.withPreservePermissions`/`withFollowSymlinks`/`withIncludeHidden`, and
> `ExtractionOptions.withSkipDuplicates`/`withAtomic` no longer accept `Option<bool>` resolved via
> `.unwrap_or(true)`. Previously, calling one of these setters with zero arguments silently
> flipped the flag to the permissive `true` state instead of erroring — violating this project's
> secure-by-default posture. Callers must now pass an explicit `boolean`; omitting it is a
> compile-time TypeScript error and a runtime napi error from plain JavaScript, which also catches
> the more realistic failure of forwarding an optional property that was never actually set (e.g.
> `cfg.withAllowSymlinks(userOpts.allowSymlinks)` where `userOpts.allowSymlinks` is `undefined`).

> [!note] Unreleased (v0.6.0): `createArchiveWithProgress` (#455, #456); the `Sync` variant was removed in #953
> Mirror the existing `extractArchiveWithProgress` async/sync pattern, reusing
> the core creation request (`CreateRequest::with_progress` since #912) and the existing `NodeProgressAdapter`
> threadsafe-function bridge — no new core security logic. JS integration tests cover the
> per-entry callback shape and the `progress=null`/omitted paths.

### JavaScript Error Mapping

Errors are rejected (or thrown, for `Sync` functions) `Error` objects. Since v0.8.0 the `message` is the description only; the class of the failure is the `code` property, built in `crates/exarch-node/src/error.rs` from `ArchiveError::into_ffi_message()` (one `FfiKind` per `ErrorCode`). Before v0.8.0 the code was the upper-snake prefix of the message (`PATH_TRAVERSAL: ...`) with `[relaxableBy=<id>]` and ` | writes=...` fragments.

| Rust `ArchiveError` variant | `code` |
|---|---|
| `PathTraversal` | `PATH_TRAVERSAL` |
| `SymlinkEscape` | `SYMLINK_ESCAPE` |
| `HardlinkEscape` | `HARDLINK_ESCAPE` |
| `ZipBomb` | `ZIP_BOMB` (also an entry claiming data from zero compressed bytes, v0.7.0, #653), with a `subCode` (`ZipBombSubCode`: `ENTRY`, `SOLID_BLOCK`, `SKIPPED_ENTRIES`) |
| `ZipInconsistency` | `ZIP_INCONSISTENCY` (v0.7.0, #671) |
| `InvalidPermissions` | `INVALID_PERMISSIONS` |
| `QuotaExceeded` | `QUOTA_EXCEEDED`, with a `subCode` (`QuotaSubCode`, ten values including `SOLID_BLOCK_MEMORY` and `HEADER_SIZE`) |
| `SecurityViolation` | `SECURITY_VIOLATION`, with `relaxableBy` set only when a setting relaxes the refusal (v0.7.0, #741, #757) and `subCode` always set to a `SecurityViolationSubCode` (v0.8.0, #865); a path rejected at the JS boundary (null byte, too long) is also `SECURITY_VIOLATION` |
| `UnknownFormat`, `ReaderFormat(Unrecognized)` | `UNKNOWN_FORMAT` |
| `InvalidConfiguration`, `ReaderFormat(NeedsSeek \| NotAtStart)` | `INVALID_CONFIGURATION` (also a rejected setter value), with `setting` naming the `ConfigSetting` when it names one (v0.8.0, #870, #894) |
| `InvalidArchive` | `INVALID_ARCHIVE`, with `subCode` (an `InvalidArchiveSubCode`) set when the failure is classified: `TAR_AMBIGUITY`, `TAR_TRAILER`, `LINK_TARGET`, `DUPLICATE_ENTRY`, `ENTRY_NAME`, `DECLARED_SIZE`, `INTEGRITY`, `ZIP_READER`, `TAR_READER` or `SEVENZ_READER` (#865, #887, #889, #894, #946; see [[001-security-pipeline/spec]] FR-028) |
| `Io` | `IO_ERROR`, with `ioKind` (an `IoKind`, fallback `'Other'`) |
| `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `InvalidCompressionLevel` | `SOURCE_NOT_FOUND`, `SOURCE_NOT_ACCESSIBLE`, `OUTPUT_EXISTS`, `INVALID_COMPRESSION_LEVEL`; `SOURCE_NOT_FOUND` and `OUTPUT_EXISTS` carry a redacted `path` (FR-122); an unreadable creation source is `SOURCE_NOT_ACCESSIBLE` (was `IO_ERROR`), with the path and the I/O text redacted by the shared core redaction (#956) |
| `PartialExtraction` | The inner error's `code`; `writes` is `'kept'` with `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings` set, `'rolled_back'` after an atomic rollback, or `'discarded'` after an in-memory extraction, the last two without counters (v0.6.0, #508; v0.7.0, #735, #747; v0.8.0, #760, #800) |
| progress callback threw | `PROGRESS_CALLBACK_ERROR` (Node-only), the throw as `cause` (FR-100) |
| entry callback threw or rejected | `ENTRY_CALLBACK_ERROR` (Node-only), the thrown value as `cause` (FR-103, v0.8.0, #842) |
| `AsyncIterable` input threw | `STREAM_ERROR` (Node-only), the throw as `cause` (FR-103, v0.8.0, #842) |
| `signal` aborted | `ABORT_ERR` (Node-only, an `AbortError`), `signal.reason` as `cause` (FR-104, v0.8.0, #848) |
| error raised by the binding itself (negative size, internal panic, failed argument conversion) | napi status string such as `GenericFailure` or `InvalidArg` (`ExarchNativeError`) |

> [!note] PartialExtraction fix in v0.4.0 and v0.4.1 (#210, #251)
> In v0.4.0 the error message for `PartialExtraction` was extended to include
> `filesExtracted` and `bytesWritten` for caller inspection (#210). However the
> message prefix was incorrectly changed to always read `PARTIAL_EXTRACTION:`
> regardless of the actual inner error type (#216). Fixed in v0.4.1 (#251): the
> message now begins with the specific error code (`SYMLINK_ESCAPE`, `QUOTA_EXCEEDED`,
> etc.) and appends the report fields, so callers can distinguish the error type
> by inspecting the message prefix. The 7z handler was also fixed to populate a
> non-empty report when at least one entry was written before the failure (#207).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path is `null` or `undefined` | TypeError thrown by napi-rs before boundary check |
| Path contains null byte | Synchronous `Error` thrown before Promise creation (`BoundaryPath::parse`, #927) |
| A limit setter given a negative, fractional, non-finite, zero or above-2^53-1 number | `INVALID_CONFIGURATION` with `setting` (#917) |
| `listArchive` of an archive with a non-UTF-8 entry name | Rejects with `INVALID_ARCHIVE` (`ENTRY_NAME`); verify and progress paths escape the bytes instead (#925) |
| `createArchive` fails midway over an existing output | The previous archive is untouched (#931) |
| Path exceeds 4096 bytes | Synchronous `Error` thrown before Promise creation |
| Rust returns `ArchiveError::PathTraversal` | Promise rejects with an `Error` whose `code` is `PATH_TRAVERSAL` |
| Rust returns `ArchiveError::PartialExtraction` | Promise rejects with the inner error's `code` (e.g. `SYMLINK_ESCAPE`); `writes: 'kept'` with `filesExtracted`, `bytesWritten`, `filesSkipped` and `warnings` properties (v0.6.0, #508; properties since v0.8.0, #760), or only `writes: 'rolled_back'` after an atomic rollback (v0.7.0, #747) or `'discarded'` after an in-memory extraction (v0.8.0) |
| `SecurityViolation` a `SecurityConfig` setting relaxes | `err.code === 'SECURITY_VIOLATION'` and `err.relaxableBy` is the setting id; the message carries no token (v0.7.0, #741, #757; property since v0.8.0, #760) |
| `verifyArchive` without `VerificationOptions().withIntegrityCheck()` | `integrityStatus` is `'SKIPPED'` and `integrityGaps` is absent (v0.7.0, #670) |
| Thread pool exhausted | Promise eventually resolves when thread becomes available; no timeout |
| `sources` array is empty for `createArchive` | [NEEDS CLARIFICATION: reject immediately or produce empty archive?] |
| Boolean setter (e.g. `withAllowSymlinks`) called with no argument, or explicit `undefined`/`null` | Runtime napi error / compile-time TypeScript error, not a silent `true` default (v0.6.0, #442, BREAKING) |
| Progress callback throws an `Error`, object, or bare primitive during `extractArchiveWithProgress`/`createArchiveWithProgress` | Captured; rejects the returned Promise instead of crashing the process (v0.6.0, #465, #473); since v0.8.0 the rejection has `code` `PROGRESS_CALLBACK_ERROR` when the operation succeeded and the throw as `cause` |
| `extractArchiveToMemory` with `atomic` or a `maxBytes` that is not a positive whole number, or `createArchiveToBytes` with `'SevenZ'` | Rejects with `INVALID_CONFIGURATION` (v0.8.0); a `format` or `pathModel` outside the string unions is a napi argument error, not a core code |
| Format cannot be detected from the bytes | Rejects with `UNKNOWN_FORMAT` (v0.8.0) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All async functions resolve with correct report objects | `npm test` passes |
| SC-002 | Event loop not blocked during extraction | Test with concurrent timer; timer fires during extraction |
| SC-003 | All `ArchiveError` variants produce JS Errors with the right `code` and typed properties | Test for each variant (`error-properties.test.js`, `error-cause-chain.test.js`) |
| SC-004 | Path boundary validation throws synchronously | Unit test: no Promise.reject, synchronous throw |
| SC-005 | TypeScript definitions are valid and complete | `tsc --noEmit` passes on test file |

## 8. Agent Boundaries

### Always (without asking)
- Validate paths synchronously at the JS boundary before creating a Promise
- Run all I/O on the libuv thread pool via napi-rs async pattern
- Map every `ArchiveError` variant to a JS Error `code` through `into_ffi_message()`, never by re-matching `ArchiveError` in the binding
- Keep all security logic in `exarch-core`; Node.js crate contains only type mapping

### Ask First
- Adding new async functions not yet in `exarch-core`
- Changing the TypeScript interface (breaking change for downstream consumers)
- Expanding `ThreadsafeFunction` callback signature (breaks callers)

### Never
- Block the Node.js event loop with synchronous Rust I/O
- Implement security validation in the Node.js crate
- Expose raw Rust types without a JavaScript wrapper

## 9. Open Questions


- [NEEDS CLARIFICATION: What is the minimum supported Node.js version? (LTS policy — 18+, 20+?)]
- [NEEDS CLARIFICATION: Should empty `sources` array in `createArchive` produce an empty archive or reject with an error?]

> [!note] Resolved in v0.4.1
> Progress callbacks for Node.js are now supported. `extractArchiveWithProgress` accepts an
> optional `ThreadsafeFunction` callback with signature
> `(path: string, total: number, current: number, bytesWritten: number) => void` (#263).
> Numeric arguments are `number`, not `bigint` — corrected in #326.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — security pipeline invoked by Node.js bindings
- [[003-config-api/spec]] — `SecurityConfig` and `CreationConfig` types
- [[020-reader-sink-and-in-memory-api/spec]] — core API behind the in-memory functions
- [[021-create-staging-and-output-policy/spec]] — staged `createArchive` and `addExcludePattern` shapes
- [[004-progress-tracking/spec]] — `ProgressCallback` and `NodeProgressAdapter` (progress callbacks supported via `ThreadsafeFunction` since v0.4.1; creation-side progress and callback-throw hardening since v0.6.0)
- [[001-exarch-system/spec]] — original monolithic spec (archived)
