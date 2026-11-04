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
updated: 2026-11-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Node.js Bindings

> [!info] Metadata
> **Subsystem**: exarch-node
> **MSRV**: Rust 1.98.0
> **Build**: napi-rs 3.x + tokio runtime
> **Source**: extracted from [[001-exarch-system/spec]]

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
GIVEN new SecurityConfig().maxFileSize(200 * 1024 * 1024).allowSymlinks(false)
WHEN passed to extractArchive()
THEN extraction respects those settings
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-080 | THE SYSTEM SHALL expose async Node.js functions returning Promises: `extractArchive`, `extractArchiveWithProgress`, `createArchive`, `createArchiveWithProgress`, `createArchiveWithProgressSync`, `listArchive`, `verifyArchive` (`createArchiveWithProgress`/`Sync` added v0.6.0, #455, mirroring the existing `extractArchiveWithProgress` async/sync pattern via the shared `NodeProgressAdapter`) | must |
| FR-081 | ALL async operations SHALL run on the libuv thread pool, not the main event loop thread | must |
| FR-082 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL throw a synchronous JavaScript Error before spawning a thread | must |
| FR-083 | Every rejected Promise and synchronous throw SHALL be an `Error` (`ExarchError` in `index.d.ts`) whose `message` is the human-readable description only and whose machine-readable data is in typed properties built from `exarch_core::ArchiveError::into_ffi_message()` (BREAKING in v0.8.0, #758, #760, #768): `code` (`ErrorCode`, the stable upper-snake core code, or `PROGRESS_CALLBACK_ERROR`), `relaxableBy?` (`PolicySetting`), `writes?` (`PartialWrites`: `'kept'`, `'rolled_back'`, `'discarded'`), and, when `writes === 'kept'`, `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings`; when `PartialExtraction` wraps an inner error, `code` is the inner error's code. The types `ErrorCode`, `PolicySetting`, `PartialWrites` and `ExarchError` (a union discriminated on `writes`, including `ExarchNativeError` for binding-raised errors whose `code` is napi's status string) are exported | must |
| FR-084 | `SecurityConfig` and `CreationConfig` SHALL be exposed as JavaScript classes with fluent builder methods; `SecurityConfig` SHALL expose `allowSolidArchives` getter consistent with `allowSymlinks`, `allowHardlinks`, `allowAbsolutePaths`, `allowWorldWritable` | must |
| FR-085 | `ExtractionReport`, `CreationReport`, `ArchiveManifest`, and `VerificationReport` SHALL be exposed as JavaScript objects with typed fields | must |
| FR-088 | `ExtractionOptions` SHALL be exposed as a JavaScript class with builder methods `withAtomic(bool?)` and `withSkipDuplicates(bool?)`; both `extractArchive` and `extractArchiveWithProgress` SHALL accept an optional `options` parameter | must |
| FR-089 | ALL async operations SHALL wrap the core call with `catch_unwind` inside `spawn_blocking`; panics in `exarch-core` SHALL be converted to JavaScript errors and SHALL NOT abort the Node.js process | must |
| FR-090 | `extractArchiveWithProgress(archivePath, outputDir, config?, options?, progress?)` SHALL accept an optional `ThreadsafeFunction` callback with signature `(path: string, total: number, current: number, bytesWritten: number) => void`; numeric callback arguments are `number` (not `bigint`) | must |
| FR-086 | napi-rs SHALL generate TypeScript `.d.ts` files for all exported functions and classes | must |
| FR-087 | ALL path arguments SHALL accept `string` type in JavaScript | must |
| FR-091 | `SecurityConfig.setAllowSymlinks`/`setAllowHardlinks`/`setAllowAbsolutePaths`/`setAllowWorldWritable`/`setAllowSolidArchives`/`setPreservePermissions`, `CreationConfig.setPreservePermissions`/`setFollowSymlinks`/`setIncludeHidden`, and `ExtractionOptions.withSkipDuplicates`/`withAtomic` SHALL take a mandatory `boolean` argument, not `Option<bool>` resolved via `.unwrap_or(true)`; omitting the argument, or passing explicit `undefined`/`null`, SHALL be a compile-time TypeScript error / runtime napi error rather than silently flipping the flag to the permissive `true` state (v0.6.0, #442, BREAKING) | must |
| FR-092 | WHEN a `PartialExtraction` error is converted to a JS error, THE SYSTEM SHALL set `writes` and, only while the written files remain (`'kept'`), the properties `filesExtracted`, `bytesWritten`, `filesSkipped` and `warnings` (an `Array<string>`); an atomic rollback sets only `writes: 'rolled_back'` and an in-memory extraction that dropped its entries only `writes: 'discarded'`. Before v0.8.0 these were appended to the message as ` \| writes=kept, filesExtracted=N, ...` (v0.6.0, #508; v0.7.0, #747; v0.8.0, #760, #768, #800, #808) | must |
| FR-093 | WHEN a progress callback throws (an `Error`/object, or a bare primitive) during `extractArchiveWithProgress` or `createArchiveWithProgress`, THE SYSTEM SHALL capture it (via `call_async_catch` plus a JS shim that pre-empts napi-rs's primitive-throw escalation) and reject the returned Promise instead of crashing the process with `napi_fatal_exception`; `createArchiveWithProgressSync` cannot use the awaiting dispatch (would deadlock the blocked event loop) and remains a documented, unaffected exception — a throw there surfaces as an ordinary `uncaughtException` (v0.6.0, #465, #473) | must |
| FR-094 | ALL path-carrying `ArchiveError` variants SHALL be redacted for release-build error messages via the shared `exarch_core::error::redaction` module, matching the Python binding's policy (archive-relative paths never redacted; host-derived paths redacted to filename-only or `ErrorKind` description) (v0.6.0, #453, #463) | must |
| FR-095 | `verifyArchive(archivePath, config?, options?)` (and `verifyArchiveSync`) SHALL accept a `VerificationOptions` class; `withIntegrityCheck(budget?)` decodes the payload to the decoder's EOF (default budget 500 MiB, independent of `maxTotalSize`; error for a zero or negative budget), otherwise `integrityStatus` is `'SKIPPED'` (v0.7.0, #670) | must |
| FR-096 | `VerificationReport` SHALL expose `status`, `integrityStatus`, `integrityGaps?` (absent unless the check ran: `counts: UnverifiedCount[]`, `entries: UnverifiedEntry[]`, `omitted`), `securityStatus`, `issues`, `totalEntries`, `suspiciousEntries`, `totalSize` and `format`; report enum fields are typed string unions in `index.d.ts` (`VerificationStatus`, `CheckStatus`, `IntegrityStatus`, `IssueSeverity`, `IssueCategory`, `UnverifiedReason`, `ManifestEntryType`, `ArchiveType`, `ZipConsistencyPolicy`) (v0.7.0, #624, #672, #684) | must |
| FR-097 | `SecurityConfig` SHALL expose `setParallelDecodeMemory(size?)` (`null`/omitted decodes on one thread; default 128 MiB, 1 GiB for `permissive()`; error for a non-positive size) with a `parallelDecodeMemory` getter, and `setZipConsistency('enforce' \| 'ignore')` (default `'enforce'`) with a `zipConsistency` getter (v0.7.0, #671, #688) | must |
| FR-098 | A `SECURITY_VIOLATION` that a `SecurityConfig` setting relaxes SHALL carry the property `relaxableBy` with `<id>` one of `symlinks`, `hardlinks`, `solid_archives`, `banned_components`, `max_path_depth`, `windows_reserved_names`, `max_tar_metadata_bytes` (`PolicySetting`); the property is absent when no setting relaxes the refusal and a violation reason cannot forge it. The `[relaxableBy=<id>]` message token of v0.7.0 no longer exists (v0.7.0, #741, #757; v0.8.0, #760, #768) | must |
| FR-099 | Report size and duration getters SHALL clamp values above `i64::MAX` to `i64::MAX` instead of wrapping (v0.7.0, #583, #697) | must |
| FR-100 | A progress callback that throws SHALL surface as the rejection or throw with `code` `PROGRESS_CALLBACK_ERROR`, the exception as `cause` (the `\| progressCallbackError` message marker is removed), and, when the operation itself succeeded, the counters: `filesExtracted`/`bytesWritten`/`filesSkipped`/`warnings` for an extraction (`writes: 'kept'`), `filesAdded` and `bytesWritten` for a creation, `writes: 'discarded'` for an in-memory extraction; if the operation failed, the core error stays primary with the callback's exception as `cause` (v0.8.0, #760, #768, #783, #790) | must |
| FR-101 | THE SYSTEM SHALL expose in-memory functions on `Uint8Array` input: `listArchiveBytes(data, config?, format?)`, `verifyArchiveBytes(data, config?, options?, format?)`, `extractArchiveToMemory(data, config?, options?, maxBytes?, pathModel?, format?)` resolving `MemoryExtraction { report, entries }` of `MemoryEntry { path, kind, data?, mode?, target? }`, and `createArchiveToBytes(sources, format, config?)` resolving `CreatedArchive { data, report }`, each with a `Sync` counterpart; `listArchiveBytesWithProgress`, `verifyArchiveBytesWithProgress` and `extractArchiveToMemoryWithProgress` take the same `(err, [path, total, current, bytesWritten])` callback as the path-based progress functions. `data` is copied before the call returns; `maxBytes` must be a positive whole number (default the config's `maxTotalSize`); `pathModel` is `'host'` or `'portable'`; `atomic` is unsupported; `format` is detected from the leading bytes when omitted; `'SevenZ'` cannot be created (`INVALID_CONFIGURATION`); a `MemoryEntry.data` is a plain `Uint8Array`, not a `Buffer` ([[020-reader-sink-and-in-memory-api/spec]]; v0.8.0, #776, #787, #790) | must |
| FR-102 | Quota errors for a single oversized file SHALL use the core wording `single file size` (v0.8.0, #760, #768) | should |

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
| `SecurityConfig` (JS class) | JavaScript class wrapping Rust `SecurityConfig` | Fluent builder: `setMaxFileSize()`, `setMaxTotalSize()`, `setAllowSymlinks()`, `setZipConsistency()`, `setParallelDecodeMemory()`, etc. |
| `CreationConfig` (JS class) | JavaScript class wrapping Rust `CreationConfig` | Fluent builder: `setCompressionLevel()`, `setFollowSymlinks()`, etc. |
| `ExtractionReport` (JS object) | Result of extraction | `filesExtracted`, `directoriesCreated`, `bytesWritten`, `duration`, `warnings` |
| `CreationReport` (JS object) | Result of creation | `filesAdded`, `bytesWritten`, `duration` |
| `ArchiveManifest` (JS object) | Archive listing result | `totalEntries`, `totalSize`, `format`, `entries` |
| `VerificationReport` (JS object) | Verification result | `status`, `integrityStatus`, `integrityGaps`, `securityStatus`, `issues`, `totalEntries`, `suspiciousEntries`, `totalSize`, `format` |
| `MemoryExtraction` / `MemoryEntry` / `CreatedArchive` (JS objects) | Results of the in-memory functions (v0.8.0) | `report`, `entries` / `path`, `kind` (`'file'`, `'directory'`, `'symlink'`), `data`, `mode`, `target` / `data`, `report` |
| `ExarchError` (TS type) | Union of the shapes a rejection or throw can have (v0.8.0) | discriminated on `writes`; `code: ErrorCode`, `relaxableBy?`, `cause?` |
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
    progress?: (err: Error | null, arg: [string, number, number, number]) => void
): Promise<ExtractionReport>

function createArchive(
    outputPath: string,
    sources: string[],
    config?: CreationConfig
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
function extractArchiveToMemory(data: Uint8Array, config?: SecurityConfig, options?: ExtractionOptions, maxBytes?: number, pathModel?: PathModel, format?: ArchiveType): Promise<MemoryExtraction>
function createArchiveToBytes(sources: string[], format: ArchiveType, config?: CreationConfig): Promise<CreatedArchive>

class SecurityConfig {
    setMaxFileSize(size: number): this
    setMaxTotalSize(size: number): this
    setMaxCompressionRatio(ratio: number): this
    setMaxFileCount(count: number): this
    setMaxPathDepth(depth: number): this
    setAllowSymlinks(allow: boolean): this
    setAllowHardlinks(allow: boolean): this
    setAllowSolidArchives(allow: boolean): this
    setZipConsistency(policy: ZipConsistencyPolicy): this
    setParallelDecodeMemory(size?: number | null): this
    setMaxSolidBlockMemory(size: number): this
    // Getters
    get allowSymlinks(): boolean
    get allowHardlinks(): boolean
    get allowAbsolutePaths(): boolean
    get allowWorldWritable(): boolean
    get allowSolidArchives(): boolean
    get zipConsistency(): ZipConsistencyPolicy
    get parallelDecodeMemory(): number | null
    get maxSolidBlockMemory(): number
}

class VerificationOptions {
    withIntegrityCheck(budget?: number | null): this
    get integrityCheck(): boolean
    get decompressionBudget(): number | null
}

class CreationConfig {
    setCompressionLevel(level: number): this
    setFollowSymlinks(follow: boolean): this
    setIncludeHidden(include: boolean): this
    addExcludePattern(pattern: string): this
    setMaxFileSize(size: number | null): this  // null = no limit; 0 is INVALID_CONFIGURATION
}

class ExtractionOptions {
    withAtomic(atomic: boolean): this
    withSkipDuplicates(skip: boolean): this
    get atomic(): boolean
}
```

> [!note] v0.5.0: `ExtractionOptions` and `extractArchiveWithProgress`
> Both functions now accept an optional `ExtractionOptions` parameter. The progress callback
> arguments (`total`, `current`, `bytesWritten`) are `number` (NAPI-RS maps `i64` to `number`),
> not `bigint`. `index.d.ts` is committed to the repository so TypeScript consumers have correct
> types without building from source.

> [!note] Unreleased (v0.6.0): boolean setters now require an explicit argument (#442, BREAKING)
> `SecurityConfig.setAllowSymlinks`/`setAllowHardlinks`/`setAllowAbsolutePaths`/
> `setAllowWorldWritable`/`setAllowSolidArchives`/`setPreservePermissions`,
> `CreationConfig.setPreservePermissions`/`setFollowSymlinks`/`setIncludeHidden`, and
> `ExtractionOptions.withSkipDuplicates`/`withAtomic` no longer accept `Option<bool>` resolved via
> `.unwrap_or(true)`. Previously, calling one of these setters with zero arguments silently
> flipped the flag to the permissive `true` state instead of erroring — violating this project's
> secure-by-default posture. Callers must now pass an explicit `boolean`; omitting it is a
> compile-time TypeScript error and a runtime napi error from plain JavaScript, which also catches
> the more realistic failure of forwarding an optional property that was never actually set (e.g.
> `cfg.setAllowSymlinks(userOpts.allowSymlinks)` where `userOpts.allowSymlinks` is `undefined`).

> [!note] Unreleased (v0.6.0): `createArchiveWithProgress`/`createArchiveWithProgressSync` (#455, #456)
> Mirror the existing `extractArchiveWithProgress` async/sync pattern, reusing
> `exarch_core::create_archive_with_progress` and the existing `NodeProgressAdapter`
> threadsafe-function bridge — no new core security logic. JS integration tests cover the
> per-entry callback shape and the `progress=null`/omitted paths.

### JavaScript Error Mapping

Errors are rejected (or thrown, for `Sync` functions) `Error` objects. Since v0.8.0 the `message` is the description only; the class of the failure is the `code` property, built in `crates/exarch-node/src/error.rs` from `ArchiveError::into_ffi_message()` (one `FfiKind` per `ErrorCode`). Before v0.8.0 the code was the upper-snake prefix of the message (`PATH_TRAVERSAL: ...`) with `[relaxableBy=<id>]` and ` | writes=...` fragments.

| Rust `ArchiveError` variant | `code` |
|---|---|
| `PathTraversal` | `PATH_TRAVERSAL` |
| `SymlinkEscape` | `SYMLINK_ESCAPE` |
| `HardlinkEscape` | `HARDLINK_ESCAPE` |
| `ZipBomb` | `ZIP_BOMB` (also an entry claiming data from zero compressed bytes, v0.7.0, #653) |
| `ZipInconsistency` | `ZIP_INCONSISTENCY` (v0.7.0, #671) |
| `InvalidPermissions` | `INVALID_PERMISSIONS` |
| `QuotaExceeded` | `QUOTA_EXCEEDED` |
| `SecurityViolation` | `SECURITY_VIOLATION`, with `relaxableBy` set only when a setting relaxes the refusal (v0.7.0, #741, #757); a path rejected at the JS boundary (null byte, too long) is also `SECURITY_VIOLATION` |
| `UnknownFormat`, `ReaderFormat(Unrecognized)` | `UNKNOWN_FORMAT` |
| `InvalidConfiguration`, `ReaderFormat(NeedsSeek \| NotAtStart)` | `INVALID_CONFIGURATION` (also a rejected setter value) |
| `InvalidArchive` | `INVALID_ARCHIVE`, with `subCode` set when the failure is classified, for example `ZIP_READER` for a ZIP reader failure (#889, #946; see [[001-security-pipeline/spec]] FR-028) |
| `Io` | `IO_ERROR` |
| `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `InvalidCompressionLevel` | `SOURCE_NOT_FOUND`, `SOURCE_NOT_ACCESSIBLE`, `OUTPUT_EXISTS`, `INVALID_COMPRESSION_LEVEL` |
| `PartialExtraction` | The inner error's `code`; `writes` is `'kept'` with `filesExtracted`, `bytesWritten`, `filesSkipped`, `warnings` set, `'rolled_back'` after an atomic rollback, or `'discarded'` after an in-memory extraction, the last two without counters (v0.6.0, #508; v0.7.0, #735, #747; v0.8.0, #760, #800) |
| progress callback threw | `PROGRESS_CALLBACK_ERROR` (Node-only), the throw as `cause` (FR-100) |
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
| Path contains null byte | Synchronous `Error` thrown before Promise creation |
| Path exceeds 4096 bytes | Synchronous `Error` thrown before Promise creation |
| Rust returns `ArchiveError::PathTraversal` | Promise rejects with an `Error` whose `code` is `PATH_TRAVERSAL` |
| Rust returns `ArchiveError::PartialExtraction` | Promise rejects with the inner error's `code` (e.g. `SYMLINK_ESCAPE`); `writes: 'kept'` with `filesExtracted`, `bytesWritten`, `filesSkipped` and `warnings` properties (v0.6.0, #508; properties since v0.8.0, #760), or only `writes: 'rolled_back'` after an atomic rollback (v0.7.0, #747) or `'discarded'` after an in-memory extraction (v0.8.0) |
| `SecurityViolation` a `SecurityConfig` setting relaxes | `err.code === 'SECURITY_VIOLATION'` and `err.relaxableBy` is the setting id; the message carries no token (v0.7.0, #741, #757; property since v0.8.0, #760) |
| `verifyArchive` without `VerificationOptions().withIntegrityCheck()` | `integrityStatus` is `'SKIPPED'` and `integrityGaps` is absent (v0.7.0, #670) |
| Thread pool exhausted | Promise eventually resolves when thread becomes available; no timeout |
| `sources` array is empty for `createArchive` | [NEEDS CLARIFICATION: reject immediately or produce empty archive?] |
| Boolean setter (e.g. `setAllowSymlinks`) called with no argument, or explicit `undefined`/`null` | Runtime napi error / compile-time TypeScript error, not a silent `true` default (v0.6.0, #442, BREAKING) |
| Progress callback throws an `Error`, object, or bare primitive during `extractArchiveWithProgress`/`createArchiveWithProgress` | Captured; rejects the returned Promise instead of crashing the process (v0.6.0, #465, #473); since v0.8.0 the rejection has `code` `PROGRESS_CALLBACK_ERROR` when the operation succeeded and the throw as `cause` |
| `extractArchiveToMemory` with `atomic` or a `maxBytes` that is not a positive whole number, or `createArchiveToBytes` with `'SevenZ'` | Rejects with `INVALID_CONFIGURATION` (v0.8.0); a `format` or `pathModel` outside the string unions is a napi argument error, not a core code |
| Format cannot be detected from the bytes | Rejects with `UNKNOWN_FORMAT` (v0.8.0) |
| Progress callback throws during `createArchiveWithProgressSync` | Surfaces as an ordinary `uncaughtException` after the function has already returned its `CreationReport` — cannot be merged into the result (documented limitation, unaffected by #465/#473 since it never enters the awaiting dispatch path) |

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
- [[004-progress-tracking/spec]] — `ProgressCallback` and `NodeProgressAdapter` (progress callbacks supported via `ThreadsafeFunction` since v0.4.1; creation-side progress and callback-throw hardening since v0.6.0)
- [[001-exarch-system/spec]] — original monolithic spec (archived)
