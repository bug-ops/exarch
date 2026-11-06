# exarch-rs

[![npm](https://img.shields.io/npm/v/exarch-rs)](https://www.npmjs.com/package/exarch-rs)
[![Node](https://img.shields.io/node/v/exarch-rs)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![License](https://img.shields.io/npm/l/exarch-rs)](../../LICENSE-MIT)

Memory-safe archive extraction and creation library for Node.js.

**Important:** exarch is designed as a secure replacement for vulnerable archive libraries like `tar-fs`, which has known CVEs with CVSS scores up to 9.4.

This package provides Node.js bindings for [exarch-core](../exarch-core), a Rust library with built-in protection against common archive vulnerabilities.

## Installation

```bash
# npm
npm install exarch-rs

# yarn
yarn add exarch-rs

# pnpm
pnpm add exarch-rs

# bun
bun add exarch-rs
```

**Note:** This package includes TypeScript definitions. No need for a separate `@types` package.

## Requirements

- Node.js >= 20

### Runtime support

Node.js is the fully supported runtime, exercised by the complete test
matrix. Bun and Deno are smoke-tested in CI (basic create/list/verify/extract
plus the progress callback and a security-violation error path) but are not
part of the full Node.js test matrix. The smoke test does not exercise a
Rust panic crossing the addon boundary, so `catch_unwind` behavior under
Bun/Deno is unverified.

## Quick Start

### Extraction

```javascript
const { extractArchive } = require('exarch-rs');

// Async (recommended)
const result = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Creation

```javascript
const { createArchive } = require('exarch-rs');

// Async (recommended)
const result = await createArchive('backup.tar.gz', ['src/', 'package.json']);
console.log(`Created archive with ${result.filesAdded} files`);
```

## Usage

### Async API (Recommended)

```javascript
const { extractArchive } = require('exarch-rs');

const result = await extractArchive('archive.tar.gz', '/output/path');

console.log(`Files extracted: ${result.filesExtracted}`);
console.log(`Bytes written: ${result.bytesWritten}`);
console.log(`Duration: ${result.durationMs}ms`);
```

### Sync API

```javascript
const { extractArchiveSync } = require('exarch-rs');

const result = extractArchiveSync('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

**Tip:** Prefer the async API to avoid blocking the event loop during extraction.

### ES Modules

```javascript
import { extractArchive } from 'exarch-rs';

const result = await extractArchive('archive.tar.gz', '/output/path');
```

### TypeScript

```typescript
import { extractArchive, SecurityConfig, ExtractionReport } from 'exarch-rs';

const result: ExtractionReport = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Custom Security Configuration

```typescript
import { extractArchive, SecurityConfig } from 'exarch-rs';

const config = new SecurityConfig()
  .setMaxFileSize(100 * 1024 * 1024)   // 100 MB per file
  .setMaxTotalSize(1024 * 1024 * 1024) // 1 GB total
  .setMaxFileCount(10_000);             // Max 10k files

const result = await extractArchive('archive.tar.gz', '/output', config);
```

### Verifying Payload Integrity

`verifyArchive` checks security only by default and reports `integrityStatus`
as `'SKIPPED'`. Opt in to decode the payload and verify checksums:

```javascript
const { verifyArchive, VerificationOptions } = require('exarch-rs');

const options = new VerificationOptions().withIntegrityCheck(); // 500 MiB budget
const report = await verifyArchive('archive.zip', null, options);

console.log(report.integrityStatus); // 'OK', 'FAILED', 'INCOMPLETE' or 'SKIPPED'
```

**Note:** `'INCOMPLETE'` means part of the payload was not verified (budget,
resource limit, solid 7z archive while `setAllowSolidArchives` is off, TAR without
an end-of-archive marker); it comes with a Medium issue, so `status` is at least
`'WARNING'`. With the check on, a TAR entry whose content fails to decode rejects
the promise.

### Archives in Memory

`listArchiveBytes`, `verifyArchiveBytes` and `extractArchiveToMemory` (each with
a `Sync` form) take the archive as a `Buffer` or `Uint8Array`. The format is
detected from the leading bytes, or stated with `format` (`'Tar'`, `'TarGz'`,
`'TarBz2'`, `'TarXz'`, `'TarZst'`, `'Zip'`, `'SevenZ'`). Nothing is written to
disk.

```javascript
const fs = require('node:fs');
const { listArchiveBytes, verifyArchiveBytes, extractArchiveToMemory } = require('exarch-rs');

const data = fs.readFileSync('archive.tar.gz');

const manifest = await listArchiveBytes(data);
const report = await verifyArchiveBytes(data);

const result = await extractArchiveToMemory(data, null, null, 64 * 1024 * 1024);
for (const entry of result.entries) {
  console.log(entry.path, entry.kind); // 'file', 'directory' or 'symlink'; 'hardlink' only from extractArchiveToCallback
  if (entry.kind === 'file') {
    const content = Buffer.from(entry.data); // entry.data is a Uint8Array
  }
}
```

`MemoryEntry` is a union discriminated by `kind`: a file always has `data`, a
symlink or hardlink always has `target`. The in-memory and callback functions
take `SinkOptions` (`withExistingFiles`, `withDecodeReuse`) as `options`, not
`ExtractionOptions`: a sink has no directory to rename, so `staging` cannot be
requested.

**Note:** `maxBytes` caps payload plus path bytes plus 256 per entry and
defaults to the config's `maxTotalSize`; exceeding it rejects with
`QUOTA_EXCEEDED`. `pathModel: 'portable'` validates names against the strictest
rules of every platform instead of this host's.

`listArchiveBytesWithProgress`, `verifyArchiveBytesWithProgress` and
`extractArchiveToMemoryWithProgress` (async only) take a `progress` callback as
their last argument, called with `(err, [path, total, current, bytesWritten])`;
`current` counts from 1 and `total` is `null` while the entry count is unknown (a TAR stream). A throwing callback stops the
run before the next entry, and the promise rejects with
`PROGRESS_CALLBACK_ERROR` and the result is discarded.

The async forms of these functions (and of their `WithProgress` variants) also
take an `AsyncIterable<Uint8Array>` as the archive, for example
`fs.createReadStream(path)` or an HTTP response body. It must be a TAR family
format (plain or compressed). It is read from a worker thread, one chunk at a
time, and closed (`return()`) however the call ends, so a refused archive does
not leave the stream open. A throwing or rejecting stream rejects with
`STREAM_ERROR` and the thrown value as `cause`. The sync functions take bytes
only. A stream that never yields keeps the call pending, and an `onEntry`
promise that never settles does the same, unless the call is given an
`AbortSignal` (below); there is no timeout. Each in-flight stream or `onEntry`
call pins a thread of the blocking pool for the whole call, so many slow
streams (for example HTTP bodies) can exhaust the pool and stall every other
async exarch call in the process.

These seven async functions (`listArchiveBytes`, `verifyArchiveBytes`,
`extractArchiveToMemory`, `extractArchiveToCallback` and the `WithProgress`
variants of the first three) take an optional `signal?: AbortSignal` as their
last argument. Aborting rejects the promise with `code === 'ABORT_ERR'`,
`name === 'AbortError'` and `cause` set to `signal.reason`, frees the worker
thread and queues the close of the stream without waiting for it. A signal that
is already aborted rejects without opening the archive. The abort is noticed
at the start of the job, while it waits for JavaScript (the next chunk of an
`AsyncIterable`, the close of the iterable, and the promise an `onEntry` call
returned, which is abandoned, not cancelled), at every read of a `Uint8Array`
archive, and at every progress callback of the `WithProgress` variants, which
stop being called once the signal fired. The work between two reads of a
`Uint8Array` is not interrupted, and a call whose last read has happened
resolves normally. A value that is not an
`AbortSignal` (any object with `aborted` and `addEventListener` is accepted,
including a signal from another realm) throws a `TypeError` synchronously.

`extractArchiveToCallback(data, onEntry, config?, options?, pathModel?, format?, signal?)`
hands each verified entry to `onEntry(entry)` instead of collecting them, so
memory use is one file at a time (bounded by `maxFileSize`). A file arrives
whole, after its size was verified. Entries are provisional: each is
delivered as soon as it is verified, so a later failure refuses the archive
after earlier entries were already delivered; treat the results as final only
once the promise resolved. The gzip trailer (CRC and length) of a `.tar.gz`
is checked once the archive has been read to its end, so a corrupt compressed
stream is refused, but only after the entries before it were delivered. The
extraction waits for the promise
`onEntry` returns before it reads on, so a slow consumer applies backpressure.
A throw or rejection stops the extraction and rejects with
`ENTRY_CALLBACK_ERROR` and the thrown value as `cause`; a thrown primitive is
wrapped in an `Error` whose `cause` is the primitive (a Symbol is stringified). A `'symlink'` entry's
`target` is spelled as the archive stores it, relative to the link. A
`'hardlink'` entry comes last and by reference: its `target` is the
root-relative resolved path of an entry already delivered, a file or an
earlier hardlink (a chain is delivered link by link). With
`existingFiles` set to `'overwrite'` a path can be delivered more than once and a hardlink
refers to the latest delivery; implicit parent directories are not delivered.

```javascript
const sizes = new Map();
await extractArchiveToCallback(fs.createReadStream('archive.tar.gz'), async (entry) => {
  if (entry.kind === 'file') sizes.set(entry.path, entry.data.length);
});
```

`extractArchiveToCallbackSync` runs `onEntry` on the JavaScript thread and
takes bytes only, which it copies before `onEntry` first runs, so a callback
can neither detach nor change the input under the parser. A callback that returns a promise is refused with
`ENTRY_CALLBACK_ERROR` and a `TypeError` as `cause` (its rejection is silenced,
so it cannot become an unhandled rejection); use the async function for async
work.

`extractArchiveToMemoryWithProgressSync`, `listArchiveBytesWithProgressSync` and
`verifyArchiveBytesWithProgressSync` take the progress callback last; its calls
arrive only after the function has returned, and a throw there is an
`uncaughtException`.

`createArchiveToBytes(sources, format)` (and `createArchiveToBytesSync`) builds
an archive in memory and resolves to `{ data, report }`:

```javascript
const { data, report } = await createArchiveToBytes(['src/'], 'TarGz');
```

**Note:** the whole archive is held in memory, up to about 2-3x its size at the
peak, and there is no size cap. Sources must be regular files and directories;
FIFOs and device files are not supported. Use `createArchive` for large
archives.

### Error Handling

```javascript
const { extractArchive } = require('exarch-rs');

try {
  const result = await extractArchive('archive.tar.gz', '/output');
  console.log(`Success: ${result.filesExtracted} files`);
} catch (error) {
  // error.code: PATH_TRAVERSAL, SYMLINK_ESCAPE, ZIP_BOMB, QUOTA_EXCEEDED, etc.
  if (error.code === 'QUOTA_EXCEEDED' && error.writes === 'kept') {
    console.error(`Partial extraction left ${error.filesExtracted} files on disk`);
  }
  console.error(`Extraction failed: ${error.message}`);
}
```

`error.message` is the human-readable description only. The generated `index.d.ts` names `AsyncIterable` and carries a `lib="es2018.asynciterable"` reference. Everything machine-readable is a property, typed as `ExarchError` in `index.d.ts`: a union you can narrow on `writes`, whose `code` is an `ErrorCode` for every member except `ExarchNativeError`. Cast to `ExarchCoreError` (every member but the native one) to narrow on `code`: `'INVALID_ARCHIVE'` pairs with `InvalidArchiveSubCode`, `'SECURITY_VIOLATION'` with a required `SecurityViolationSubCode`, `'IO_ERROR'` with a required `ioKind`, so `code === 'PATH_TRAVERSAL' && subCode === 'INTEGRITY'` does not type-check.

| Property | Set when | Value |
|----------|----------|-------|
| `code` | always | An `ErrorCode` such as `'PATH_TRAVERSAL'`, `'QUOTA_EXCEEDED'` or `'SECURITY_VIOLATION'`. A path rejected at the boundary (null byte, too long) is `'SECURITY_VIOLATION'` and a rejected setter value (a zero or negative limit, a non-positive ratio, an unusable list entry) is `'INVALID_CONFIGURATION'` with a `setting` naming it. Errors raised by the binding itself (an internal panic, a failed argument conversion) are `ExarchNativeError`: `code` is napi's status string (`'GenericFailure'`, `'InvalidArg'`, ...), not an `ErrorCode`, and no other property is set. |
| `relaxableBy` | a `SECURITY_VIOLATION` that a `SecurityConfig` setting would admit | The `PolicySetting` id, for example `'symlinks'` |
| `subCode` | an `INVALID_ARCHIVE` with a finer classification, every core `SECURITY_VIOLATION`, every `QUOTA_EXCEEDED` and every `ZIP_BOMB` | on `INVALID_ARCHIVE`, `'TAR_AMBIGUITY'` (a TAR header read differently by different tools), `'TAR_TRAILER'` (the stream after the TAR end-of-archive marker is corrupt or truncated), `'ZIP_READER'` (a failure of the ZIP reader or of the structural check built on it), `'LINK_TARGET'`, `'DUPLICATE_ENTRY'`, `'ENTRY_NAME'`, `'DECLARED_SIZE'`, `'INTEGRITY'` (the refusal of that family), `'TAR_READER'` or `'SEVENZ_READER'` (a failure of the TAR or 7z reader); on `SECURITY_VIOLATION`, the family of the refusal, one of `'PATH_NAME'`, `'PATH_DEPTH'`, `'LINK_TARGET'`, `'LINK_POLICY'`, `'EXISTING_SYMLINK'`, `'ENTRY_TYPE'`, `'ROOT_ENTRY'`, `'ENCRYPTED'`, `'COMPRESSION_METHOD'`, `'SOLID_ARCHIVE'`, `'DECLARED_SIZE'`, `'CONCURRENT_CHANGE'`, `'TAR_METADATA'`, `'TAR_TRAILER'`, `'PLATFORM'`, `'OUTPUT_CONFLICT'`, `'SOURCE_PATH'`; on `QUOTA_EXCEEDED`, the quota (`'FILE_COUNT'`, `'TOTAL_SIZE'`, `'FILE_SIZE'`, `'INTEGER_OVERFLOW'`, `'DECODER_MEMORY'`, `'COMPRESSED_MEMBERS'`, `'TREE_NODES'`, `'SINK_CAPACITY'` or `'SOLID_BLOCK_MEMORY'`); on `ZIP_BOMB`, what the ratio was measured over (`'ENTRY'`, `'SOLID_BLOCK'` or `'SKIPPED_ENTRIES'`); typed `InvalidArchiveSubCode`, `SecurityViolationSubCode`, `QuotaSubCode` or `ZipBombSubCode` |
| `nonUtf8EntryPath` | an `INVALID_ARCHIVE` (`'ENTRY_NAME'`) refusal of an entry name that is not valid UTF-8 | The name written injectively: a backslash is `\x5C`, each invalid byte `\xNN` |
| `restore`, `backupPath`, `leftoverPath` | an `IO_ERROR` from a failed `'atomic_replace'` (`leftoverPath` also from a creation that left an empty output reservation) | `restore` is `'not_needed'`, `'restored'` or `'failed'`; `backupPath` names where the original remains after `'failed'`; `leftoverPath` a staging directory or reservation left on disk; paths are redacted like the message |
| `conflicts` | an `OUTPUT_EXISTS` from a `'refuse'` extraction | The entry names that found an occupant |
| `protectedPath`, `collision`, `unmatchedPatterns` | an `INVALID_CONFIGURATION` for a protected `'atomic_replace'` destination, for creation sources that map to one entry name, or for include patterns that matched no entry | `'filesystem_root'`, `'archive_ancestor'` or `'working_directory'`; `{ name, first, second }`; the unmatched patterns |
| `ioKind` | an `IO_ERROR` | The `IoKind` core reported, for example `'NotFound'`, `'PermissionDenied'` or `'StorageFull'`; `'Other'` for a kind with no entry in `IoKind` |
| `writes` | an extraction failed after producing output | `'kept'`, `'rolled_back'` (atomic extraction discarded the output) or `'discarded'` (an in-memory extraction wrote nothing to disk and dropped its entries) |
| `filesExtracted`, `bytesWritten`, `filesSkipped`, `skipped`, `warnings` | `writes === 'kept'` | Counters, the skips by reason and the typed `ExtractionWarning[]` |
| `errno`, `strerror`, `path` | a `SOURCE_NOT_ACCESSIBLE` | The OS error number (when the failure has one), its text and the unreadable source, redacted like the message |
| `cause` | a progress callback, an `onEntry` callback or an `AsyncIterable` archive threw | The exception it threw (a thrown primitive is wrapped in an `Error` whose `cause` is the primitive) |

`code === 'ENTRY_CALLBACK_ERROR'` means an `onEntry` callback threw or rejected and `code === 'STREAM_ERROR'` that an `AsyncIterable` archive did; both carry no counters and take priority over the core error they caused. `code === 'ABORT_ERR'` (with `name === 'AbortError'` and `cause` set to the signal's `reason`) means the call's `AbortSignal` fired; it takes priority over the errors the abort caused. `code === 'CANCELLED'` is a cancellation that no JavaScript signal caused. A core error other than a cancellation always stays primary over a callback throw that happened in the same run.

A progress callback that throws stops the operation before the next entry. The rejection has `code === 'PROGRESS_CALLBACK_ERROR'`, the throw as `cause`, and the counters of what was written (`filesExtracted`... for extraction, `filesAdded` and `bytesWritten` for creation). The in-memory extraction functions write nothing, so their rejection carries `writes === 'discarded'` and no counters.

**Breaking change:** earlier versions put the code, a `[relaxableBy=<id>]` token and a `| writes=...` suffix into `message`. Read the properties instead.

## API

### `extractArchive(archivePath, outputDir, config?, options?)`

Extract an archive asynchronously with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archivePath` | `string` | Path to the archive file |
| `outputDir` | `string` | Directory where files will be extracted |
| `config` | `SecurityConfig` | Optional security configuration |
| `options` | `ExtractionOptions` | Optional `new ExtractionOptions().withStaging('in_place' \| 'atomic' \| 'atomic_replace')` / `.withExistingFiles('skip' \| 'overwrite' \| 'refuse')` |

**Returns:** `Promise<ExtractionReport>`

### `extractArchiveSync(archivePath, outputDir, config?, options?)`

Synchronous version. Blocks the event loop until extraction completes.

**Returns:** `ExtractionReport`

### Listing entries

`listArchive` returns entries as a union discriminated by `entryType`
(`ArchiveEntry`): a `'File'` has `size`, a `'Symlink'` or `'Hardlink'` has a
`target` that is itself a union discriminated by `state` (`'recorded'` with a
`path`, `'missing'`, `'unread'`, `'unreadable'` or `'oversized'` with `bytes`),
and a `'Directory'` has neither. `mode` is the raw archive mode. An entry whose
name is not valid UTF-8 makes the listing fail with `INVALID_ARCHIVE` and
`subCode: 'ENTRY_NAME'` rather than being rendered lossily; verification
issues, integrity gaps, skip samples and progress callbacks render a path with an injective encoding instead: a backslash is `\x5C` and each invalid byte is `\xNN`, so two distinct entries never share a rendered name (the literal name `a\xFFb` renders as `a\x5CxFFb`, the name `a` + byte `0xFF` + `b` as `a\xFFb`). Names without backslashes and invalid bytes are unchanged.

`verifyArchive` issues carry the typed refusal behind a finding: `code`,
`subCode`, `relaxableBy`, `setting`, `ioKind` and `mode` (the raw permission
bits of an invalid-permissions refusal or an executable file), paired as on an error
(`VerificationIssue` in `index.d.ts`); the former `context` string is gone.

### `ExtractionReport`

```typescript
interface ExtractionReport {
  filesExtracted: number;     // Number of files extracted
  directoriesCreated: number; // Number of directories created
  symlinksCreated: number;    // Number of symlinks created
  bytesWritten: number;       // Total bytes written
  durationMs: number;         // Extraction duration in milliseconds
  filesSkipped: number;       // Entries skipped, over all reasons
  skipped: { counts: { kind: SkipKind; count: number }[]; sample: SkippedEntry[] }; // by reason
  warnings: ExtractionWarning[]; // Typed conditions worth surfacing; branch on `kind`, `message` is the text
}
```

### `extractArchiveWithProgress(archivePath, outputDir, config?, options?, progress?)`

Async extraction with an optional progress callback, invoked once per entry.

`progress` uses napi's standard threadsafe-function calling convention:
`(err, arg)`, where `err` is always `null` and `arg` is the `[path, total,
current, bytesWritten]` tuple — **not** four separate arguments.
`bytesWritten` is always `0`: the callback only fires from the entry-start
event, before any bytes for that entry have been counted.

```typescript
import { extractArchiveWithProgress } from 'exarch-rs';

const result = await extractArchiveWithProgress(
  'archive.tar.gz',
  '/output/path',
  undefined,  // SecurityConfig or undefined
  undefined,  // ExtractionOptions or undefined
  (err, [path, total, current, bytesWritten]) => {
    console.log(`[${current}/${total}] ${path}`);
  }
);
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archivePath` | `string` | Path to the archive file |
| `outputDir` | `string` | Directory where files will be extracted |
| `config` | `SecurityConfig \| undefined` | Optional security configuration |
| `options` | `ExtractionOptions \| undefined` | Optional extraction options |
| `progress` | `(err: Error \| null, arg: ProgressArgs) => void \| undefined` | Optional progress callback |

**Returns:** `Promise<ExtractionReport>`

### Exclude patterns

`CreationConfig.setExcludePatterns(patterns)` replaces the list (the defaults included)
and `addExcludePattern(pattern)` appends one; both accept four shapes: `name` (a path
component equal to it), `name*`, `*name` and `dir/sub` (that path and its
subtree). Patterns match the entry's archive path, never the ancestors of a
source directory, so for a source `src` write `build`, not `src/build`. Any
other shape, such as `*.m*`, `?.txt`, `[a`, `{a,b}`, `!a.txt`, `a,b`, a pattern
with leading or trailing whitespace, an empty one, `..` or an absolute path,
throws `INVALID_CONFIGURATION` with `setting: 'exclude_pattern'` instead of
silently excluding nothing.

### Create options

`createArchive`, `createArchiveSync` and `createArchiveWithProgress` take an
optional trailing `CreateOptions` argument:
`{ format?: CreatableFormat; overwrite?: boolean; durability?: Durability }`.
`overwrite` defaults to `true`: an existing output is replaced when creation
succeeds, and a failed creation leaves it untouched; `overwrite: false`
refuses an existing output with `OUTPUT_EXISTS`. `format` overrides the format
the output extension names, which is how a `.apk` or `.whl` is written as a
plain ZIP. `CreatableFormat` is `ArchiveType` without `'SevenZ'`, which cannot
be created: passing it is refused at the boundary with an `InvalidArg` error
from napi-rs, not an exarch error code. `createArchiveToBytes` takes a
`CreatableFormat` as an argument and has no output file.

`durability` is `'synced'` (the default) or `'unsynced'`. `'synced'` flushes
the archive and its directory entry before the call succeeds. `'unsynced'`
skips both, which is faster, but after a crash or power loss a replaced output
can be empty or truncated and a new output can be empty, and write-back errors
(network filesystems, quotas, delayed allocation) are not reported, so success
does not prove the bytes reached the disk.

### `createArchiveWithProgress(outputPath, sources, config?, progress?, options?)`

Async archive creation with an optional progress callback, invoked once per entry.

`progress` uses the same `(err, arg)` calling convention as
`extractArchiveWithProgress` above — `arg` is `[path, total, current,
bytesWritten]`, and `bytesWritten` is always `0` for the same reason.

```typescript
import { createArchiveWithProgress } from 'exarch-rs';

const result = await createArchiveWithProgress(
  'backup.tar.gz',
  ['src/', 'package.json'],
  undefined,  // CreationConfig or undefined
  (err, [path, total, current, bytesWritten]) => {
    console.log(`[${current}/${total}] ${path}`);
  }
);
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `outputPath` | `string` | Path to the output archive file |
| `sources` | `string[]` | Source files/directories to include |
| `config` | `CreationConfig \| undefined` | Optional creation configuration |
| `progress` | `(err: Error \| null, arg: ProgressArgs) => void \| undefined` | Optional progress callback |
| `options` | `CreateOptions \| undefined` | Optional `{ format, overwrite, durability }` (see Create options) |

**Returns:** `Promise<CreationReport>`

### `SecurityConfig`

Builder-style security configuration.

```typescript
const config = new SecurityConfig()
  .setMaxFileSize(bytes)                     // Max size per file
  .setMaxTotalSize(bytes)                    // Max total extraction size
  .setMaxFileCount(count)                    // Max number of files
  .setMaxCompressionRatio(n)                 // Max compression ratio (zip bomb detection)
  .addAllowedExtension(".txt")               // Restrict to a set of extensions (repeatable)
  .setAllowedExtensions([".txt", ".md"])     // Replace the allowlist; null allows every extension, [] is refused
  .addBannedComponent("__MACOSX")            // Skip this path component (repeatable)
  .setBannedComponents(["__MACOSX"])         // Replace the banned components; [] bans nothing
  .addIncludePattern("src")                  // Extract only matching entries (repeatable, or setIncludePatterns([...]))
  .addExcludePattern("*.tmp")                // Never extract matching entries; wins over include (or setExcludePatterns([...]))
  .setStripComponents(1)                     // Drop leading path components, like tar --strip-components; null keeps paths
  .setFlatten(true)                          // Land every file under its final component (replaces a strip count)
  .setAllowSolidArchives(true)               // Allow solid 7z archives (default: false)
  .setZipConsistency('ignore')               // ZIP structure policy: 'enforce' (default) or 'ignore'
  .setParallelDecodeMemory(256 * 1024 * 1024); // 7z LZMA2 lookahead memory (default 128 MiB); null decodes on one thread
```

**Getters:** `allowedExtensions` returns the allowlist, or `null` while every extension is allowed. `allowSymlinks`, `allowHardlinks`, `allowAbsolutePaths`, `allowWorldWritable`, `allowSolidArchives` — each returns the corresponding boolean policy value. `zipConsistency` returns `'enforce'` or `'ignore'`. `parallelDecodeMemory` returns the 7z lookahead memory in bytes, or `null` when decoding runs on one thread. Each extract or verify call may start up to 16 worker threads and hold its own lookahead, so concurrent calls multiply both.

### Selecting and rewriting entries

`includePatterns`, `excludePatterns`, `stripComponents` and `flatten` live on
`SecurityConfig`, so `extractArchive*`, `extractArchiveToMemory`,
`extractArchiveToCallback`, `listArchive*` and `verifyArchive*` apply the same
selection with the same code. Order of operations: the original entry name is
validated first (an unsafe name is refused even when it is not selected), then
include and exclude patterns select entries, matching the path **before**
stripping, then `stripComponents` or `flatten` rewrite the name, which is
validated again. Patterns have four shapes (`name`, `name*`, `*name` and
`dir/sub`, which selects that path and everything below it), compare raw
components and are case-sensitive on every host. An empty pattern list selects
everything.

- Entries left out are counted in `skipped` as `'not_selected'`, and entries
  with no component left after stripping, or directories under `flatten`, as
  `'stripped_away'`. They are not charged to the size limits.
- An include pattern that matches nothing fails the extraction after the
  scan with `INVALID_CONFIGURATION` (`setting` `'entry_include'`) and
  `unmatchedPatterns`; `'atomic'` rolls back. An exclude pattern that matches
  nothing is not an error.
- A hardlink whose target the selection leaves out, and any symlink or hardlink
  under `flatten`, are refused with `SECURITY_VIOLATION`
  (`subCode` `'LINK_TARGET'` and `'LINK_POLICY'`).
- `'atomic_replace'` staging with a non-default selection is refused
  (`INVALID_CONFIGURATION`, `setting` `'entry_selection'`).
- `listArchive*` still lists every entry; `verifyArchive*` reports the refusals
  extraction would raise for the same selection as issues.

## Security Features

The library provides built-in protection against:

| Protection | Description |
|------------|-------------|
| Path traversal | Blocks `../` and absolute paths |
| Symlink attacks | Prevents symlinks escaping extraction directory |
| Hardlink attacks | Validates hardlink targets |
| Zip bombs | Detects high compression ratios |
| TAR metadata bombs | Bounds GNU long-name/long-link and PAX header record reads |
| Permission sanitization | Strips setuid/setgid bits |
| Size limits | Enforces file and total size limits |

**Caution:** Unlike many Node.js archive libraries, exarch applies security validation by default.

## Supported Formats

| Format | Extensions | Extract | Create | List | Verify |
|--------|------------|:-------:|:------:|:----:|:------:|
| TAR | `.tar` | ✅ | ✅ | ✅ | ✅ |
| TAR+GZIP | `.tar.gz`, `.tgz` | ✅ | ✅ | ✅ | ✅ |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` | ✅ | ✅ | ✅ | ✅ |
| TAR+XZ | `.tar.xz`, `.txz` | ✅ | ✅ | ✅ | ✅ |
| TAR+ZSTD | `.tar.zst`, `.tzst` | ✅ | ✅ | ✅ | ✅ |
| ZIP | `.zip` | ✅ | ✅ | ✅ | ✅ |
| ZIP-family | `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | ✅ | — | ✅ | ✅ |
| 7z | `.7z` | ✅ | — | ✅ | ✅ |

**Note:** ZIP-family formats share the ZIP container but add extra structure (signing, checksum manifests, ordering rules) that exarch doesn't produce, so creation is rejected for those extensions. 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons. A 7z archive holding a Windows reparse point is refused as a whole; a Unix `S_IFLNK` symlink is read and validated through the symlink policy, so it is created only with symlinks allowed, and a 7z FIFO, socket or device node is refused.

## Comparison with tar-fs

```javascript
// UNSAFE - tar-fs has known vulnerabilities
const tar = require('tar-fs');
const fs = require('fs');
fs.createReadStream('archive.tar')
  .pipe(tar.extract('/output'));  // May extract outside target directory!

// SAFE - exarch-rs validates all paths
const { extractArchive } = require('exarch-rs');
await extractArchive('archive.tar', '/output');  // Protected by default
```

## Development

This package is built using [napi-rs](https://napi.rs/).

```bash
# Clone repository
git clone https://github.com/bug-ops/exarch
cd exarch/crates/exarch-node

# Install dependencies
npm install

# Build native module
npm run build

# Run tests
npm test
```

## Related Packages

- [exarch-core](../exarch-core) — Core Rust library
- [exarch (PyPI)](../exarch-python) — Python bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
