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
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
---

# Feature: Node.js Bindings

> [!info] Metadata
> **Subsystem**: exarch-node
> **MSRV**: Rust 1.93.0
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
- Progress callbacks from Node.js (no equivalent of `PyProgressAdapter`)
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
I WANT Rust ArchiveError variants to produce named JS Error objects
SO THAT I can differentiate errors in a catch block by type name

**Acceptance criteria:**
```
GIVEN an archive with a path traversal entry
WHEN extractArchive() rejects
THEN the rejected Error has name === "PathTraversalError"
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
| FR-080 | THE SYSTEM SHALL expose async Node.js functions returning Promises: `extractArchive`, `createArchive`, `listArchive`, `verifyArchive` | must |
| FR-081 | ALL async operations SHALL run on the libuv thread pool, not the main event loop thread | must |
| FR-082 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL throw a synchronous JavaScript Error before spawning a thread | must |
| FR-083 | Rust `ArchiveError` variants SHALL map to named JavaScript Error types; when `PartialExtraction` wraps an inner error, the error message SHALL begin with the specific inner error code (e.g. `SYMLINK_ESCAPE`, `QUOTA_EXCEEDED`) and SHALL append `filesExtracted` and `bytesWritten` fields for caller inspection | must |
| FR-084 | `SecurityConfig` and `CreationConfig` SHALL be exposed as JavaScript classes with fluent builder methods | must |
| FR-085 | `ExtractionReport`, `CreationReport`, `ArchiveManifest`, and `VerificationReport` SHALL be exposed as JavaScript objects with typed fields | must |
| FR-086 | napi-rs SHALL generate TypeScript `.d.ts` files for all exported functions and classes | must |
| FR-087 | ALL path arguments SHALL accept `string` type in JavaScript | must |

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
| `SecurityConfig` (JS class) | JavaScript class wrapping Rust `SecurityConfig` | Fluent builder: `maxFileSize()`, `maxTotalSize()`, `allowSymlinks()`, etc. |
| `CreationConfig` (JS class) | JavaScript class wrapping Rust `CreationConfig` | Fluent builder: `compressionLevel()`, `followSymlinks()`, etc. |
| `ExtractionReport` (JS object) | Result of extraction | `filesExtracted`, `directoriesCreated`, `bytesWritten`, `duration`, `warnings` |
| `CreationReport` (JS object) | Result of creation | `filesAdded`, `bytesWritten`, `duration` |
| `ArchiveManifest` (JS object) | Archive listing result | `totalEntries`, `totalSize`, `format`, `entries` |
| `VerificationReport` (JS object) | Verification result | `status`, `issues`, `totalEntries` |

### TypeScript API Surface

```typescript
// All functions are async (Promise-based)
function extractArchive(
    archivePath: string,
    outputDir: string,
    config?: SecurityConfig
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
    config?: SecurityConfig
): Promise<VerificationReport>

class SecurityConfig {
    maxFileSize(size: number): this
    maxTotalSize(size: number): this
    maxCompressionRatio(ratio: number): this
    maxFileCount(count: number): this
    maxPathDepth(depth: number): this
    allowSymlinks(allow: boolean): this
    allowHardlinks(allow: boolean): this
    allowSolidArchives(allow: boolean): this
}

class CreationConfig {
    compressionLevel(level: number): this
    followSymlinks(follow: boolean): this
    includeHidden(include: boolean): this
    exclude(pattern: string): this
    stripPrefix(prefix: string): this
}
```

### JavaScript Error Mapping

| Rust `ArchiveError` variant | JavaScript Error name |
|---|---|
| `PathTraversal` | `PathTraversalError` |
| `SymlinkEscape` | `SymlinkEscapeError` |
| `HardlinkEscape` | `HardlinkEscapeError` |
| `ZipBomb` | `ZipBombError` |
| `QuotaExceeded` | `QuotaExceededError` |
| `UnknownFormat` | `UnknownFormatError` |
| `InvalidConfiguration` | `InvalidConfigurationError` |
| `InvalidArchive` | `InvalidArchiveError` |
| `Io` | `IoError` |
| `PartialExtraction` | The specific inner error code (e.g. `SYMLINK_ESCAPE: ...`) is preserved; `filesExtracted` and `bytesWritten` are appended to the message |

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
| Rust returns `ArchiveError::PathTraversal` | Promise rejects with `PathTraversalError` |
| Rust returns `ArchiveError::PartialExtraction` | Promise rejects with the specific inner error code as prefix (e.g. `SYMLINK_ESCAPE: ...`); message appends `filesExtracted` and `bytesWritten` |
| Thread pool exhausted | Promise eventually resolves when thread becomes available; no timeout |
| `sources` array is empty for `createArchive` | [NEEDS CLARIFICATION: reject immediately or produce empty archive?] |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All async functions resolve with correct report objects | `npm test` passes |
| SC-002 | Event loop not blocked during extraction | Test with concurrent timer; timer fires during extraction |
| SC-003 | All `ArchiveError` variants produce named JS Errors | Test for each variant |
| SC-004 | Path boundary validation throws synchronously | Unit test: no Promise.reject, synchronous throw |
| SC-005 | TypeScript definitions are valid and complete | `tsc --noEmit` passes on test file |

## 8. Agent Boundaries

### Always (without asking)
- Validate paths synchronously at the JS boundary before creating a Promise
- Run all I/O on the libuv thread pool via napi-rs async pattern
- Map every `ArchiveError` variant to a named JS Error
- Keep all security logic in `exarch-core`; Node.js crate contains only type mapping

### Ask First
- Adding new async functions not yet in `exarch-core`
- Adding progress callback support for Node.js (requires careful GIL/event-loop design)
- Changing the TypeScript interface (breaking change for downstream consumers)

### Never
- Block the Node.js event loop with synchronous Rust I/O
- Implement security validation in the Node.js crate
- Expose raw Rust types without a JavaScript wrapper

## 9. Open Questions

- [NEEDS CLARIFICATION: What is the minimum supported Node.js version? (LTS policy — 18+, 20+?)]
- [NEEDS CLARIFICATION: Should progress callbacks be supported from Node.js? Requires thread-safe channel from Rust back to JS event loop.]
- [NEEDS CLARIFICATION: Should empty `sources` array in `createArchive` produce an empty archive or reject with an error?]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — security pipeline invoked by Node.js bindings
- [[003-config-api/spec]] — `SecurityConfig` and `CreationConfig` types
- [[004-progress-tracking/spec]] — `ProgressCallback` (currently no Node.js callback support)
- [[001-exarch-system/spec]] — original monolithic spec (archived)
