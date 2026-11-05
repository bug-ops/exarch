---
aliases:
  - Reader, Sink and In-Memory API
  - ArchiveReader and EntrySink Spec
tags:
  - sdd
  - spec
  - api
  - rust
  - in-memory
  - bindings
created: 2026-11-02
updated: 2026-11-05
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[019-verify-and-list-model/spec]]"
---

# Feature: Reader, Sink and In-Memory API

> [!note] Revision 2026-11-04 (50-issue batch)
> The free functions `list_reader*`, `verify_reader*`, `extract_to_sink*`, `create_to_writer*`, `create_to_bytes`, `*_with_progress` and `list_archive_for_extraction` were removed (#912); their roles are `ListRequest`, `VerifyRequest`, `SinkExtractRequest` and `CreateRequest`. `EntrySink::create_file*` takes `AdmittedSize` and `create_symlink` takes `CheckedLinkTarget` (#909); `ListedArchive` owns the extraction config (#901); `CallbackError` is exhaustive (#922); the binding sink options are a `SinkOptions` class (#926). Requirement rows below are rewritten accordingly (names in the Origin line describe the release).

> [!info] Metadata
> **Subsystem**: exarch-core (`reader`, `sink`, `sink::memory`, `writer`, `api`, `formats::target`, `formats::sevenz::{extract,host,sink}`, `security::{admitted,fs_view}`), `exarch-python` (`buffer`), `exarch-node` (`memory`, `buffer`)
> **MSRV**: Rust 1.99.1
> **Origin**: v0.8.0 — #771 (reader APIs, WASI), #787 (sink, memory sink, detection, writers, bindings), #790 (progress variants, `of_type`, `create_to_bytes`), #808 (`SinkOptions`, `SinkFull`, `CreatableFormat`, typed `ExtractTarget`)
> **Status**: implemented — documents shipped behavior; the archive-from-a-path API of [[002-format-handlers/spec]] is unchanged

## 1. Overview

### Problem Statement

Until v0.7.0 every operation took an archive path and extraction wrote under a directory.
Callers that hold an archive in memory or in a stream (an upload, an object store, a WASI
guest with no ambient filesystem, a service that must not touch the host disk) had to write the
bytes to a temporary file first, which also made `verify` and `list` depend on a writable
temporary directory. Extraction into storage the caller owns had no way to reuse the security
pipeline.

### Goal

Expose the full validation pipeline over caller-supplied readers, writers and sinks, with the
same gates as the path-based API, and surface it in the Python and Node.js bindings as
in-memory functions.

### Out of Scope

- Streaming (forward-only) ZIP or 7z input: both need `Seek`
- Extracting a sink's output to a real filesystem with the path-based defences (`DirWalker`, `O_NOFOLLOW`, `create_new`); use `extract_archive`
- 7z creation
- A Rust async interface

## 2. User Stories

### US-001: Inspect an Archive Without a Path

AS A library caller holding an archive in a `Read` (+ `Seek`) source
I WANT `list_reader` and `verify_reader` to give the same manifest and report as the path-based calls
SO THAT I never write an untrusted archive to a temporary file

**Acceptance criteria:**
```
GIVEN an ArchiveReader over a TAR, ZIP or 7z archive
WHEN list_reader() or verify_reader() runs
THEN the result has the semantics of the path-based call on the same bytes
AND no temporary directory or file is created
```

### US-002: Extract Into Caller-Owned Storage

AS A caller with an object store or virtual filesystem
I WANT to implement `EntrySink` and receive only validated entries
SO THAT every quota, ratio, path and link gate of `extract_archive` applies to my storage

**Acceptance criteria:**
```
GIVEN a TAR, ZIP or 7z ArchiveReader and a custom EntrySink
WHEN extract_to_sink() runs
THEN each delivered path is relative, normalized, free of `..` and already resolved through earlier symlinks
AND a sink failure ends the extraction, as PartialExtraction once an entry was delivered
```

### US-003: Extract to Memory With a Bound

AS A service extracting an upload
I WANT the extracted entries in a `MemorySink` bounded by a `MemoryLimit`
SO THAT a hostile archive cannot exhaust memory beyond a stated cap

**Acceptance criteria:**
```
GIVEN an archive whose entries exceed the MemoryLimit
WHEN extract_reader_to_memory() runs
THEN it fails with QuotaExceeded { resource: SinkCapacity { max } }
AND the error is PartialExtraction with writes == Discarded when an entry had been collected
```

### US-004: Detect the Format From Bytes

AS A caller with no file name
I WANT `ArchiveReader::detect` and `detect_stream` to pick the format from the leading bytes
SO THAT format detection does not depend on an extension

**Acceptance criteria:**
```
GIVEN a forward-only reader holding a ZIP
WHEN detect_stream() runs
THEN ReaderFormatError::NeedsSeek(Zip) is returned
GIVEN a seekable reader positioned at a nonzero offset holding a ZIP or 7z signature
WHEN detect() runs
THEN ReaderFormatError::NotAtStart is returned
```

### US-005: Create an Archive Into a Writer or Bytes

AS A caller that returns an archive from a service
I WANT `create_to_writer` and `create_to_bytes`
SO THAT I do not stage the archive on disk

**Acceptance criteria:**
```
GIVEN sources and a CreatableFormat
WHEN create_to_bytes() runs
THEN the bytes and a CreationReport are returned and bytes_compressed equals the byte length
```

### US-006: In-Memory Functions in Python and Node.js

AS A Python or Node.js developer
I WANT list, verify, extract and create functions that take and return bytes
SO THAT a web handler never writes an untrusted archive to disk

## 3. Functional Requirements

### 3.1 Reader

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `ArchiveReader` SHALL wrap an archive in a `Read + Send` source (TAR, optionally with a `CompressionCodec`) or a `Read + Seek + Send` source (`SeekableFormat::{Zip, SevenZ}`), built by `tar`, `seekable`, `of_type(reader, ArchiveType)`, `from_bytes(bytes, Option<ArchiveType>)`, `detect` and `detect_stream`; `format()` reports the declared `ArchiveType` | must |
| FR-002 | `ArchiveReader::detect` SHALL read the leading bytes (up to 512), restore the reader position, and select the first matching signature in table order; it SHALL fail with `ArchiveError::ReaderFormat(Unrecognized)` when none matches and `ReaderFormat(NotAtStart(format))` when a ZIP or 7z signature is found at a nonzero start position | must |
| FR-003 | `ArchiveReader::detect_stream` SHALL accept only TAR streams, replay the peeked bytes in front of the rest of the stream, and fail with `ReaderFormat(NeedsSeek(format))` for ZIP or 7z and `ReaderFormat(Unrecognized)` otherwise | must |
| FR-004 | A TAR whose first member name starts with `BZh` but is not a complete bzip2 stream header (`BZh`, a level digit, the block magic) SHALL be detected as TAR; input valid under both readings stays bzip2 (#781, #790) | must |
| FR-005 | `ListRequest::list_reader` and `VerifyRequest::verify_reader` (with or without `with_progress`) SHALL accept TAR, ZIP and 7z readers and apply the same `SecurityConfig`, `ListOptions` and `VerificationOptions` semantics as `ListRequest::list` and `VerifyRequest::verify`; verification validates against an in-memory tree and creates no temporary directory (#754, #771) | must |
| FR-006 | `ArchiveError::ReaderFormat(ReaderFormatError)` SHALL be the error for reader format failures; across the FFI it maps `Unrecognized` to `UnknownFormat` and `NeedsSeek`/`NotAtStart` to `InvalidConfiguration` | must |

### 3.2 Sink

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | `SinkExtractRequest::new(&SecurityConfig).with_options(SinkOptions).extract(reader, &mut sink)` (optionally `with_progress`) SHALL run the extraction pipeline of `extract_archive` (quotas, ratios, path and link validation, per-format gates) for TAR, ZIP and 7z and deliver each validated entry to an `EntrySink` | must |
| FR-011 | `EntrySink` SHALL provide `create_directory`, `create_file` (path, optional `SanitizedMode`, `size: AdmittedSize`) returning `Self::File: Write`, `create_file_from`, `finish_file`, `create_symlink` (target as `CheckedLinkTarget<'_>`) and `create_hardlink`; `AdmittedSize` and `CheckedLinkTarget` are built only by the validator's permit and `SafeSymlink`, so a sink cannot be handed an unadmitted size or an unchecked target (#909), and an overridable `path_model()` defaulting to `PathModel::Host` | must |
| FR-012 | A file SHALL be delivered as `create_file`, writes, `finish_file`; a `File` dropped without `finish_file` is DISCARDED (the pipeline drops it when the entry fails), so a sink MUST NOT publish data from `Drop` or `write`; the pipeline never flushes, so `finish_file` flushes and reports a failed flush | must |
| FR-013 | Every path delivered to a sink SHALL be relative, normalized, free of `..`, a root or a prefix, and already resolved through the symlinks of earlier entries; parent directories SHALL NOT be announced; hardlinks SHALL be delivered after every other entry | must |
| FR-014 | Validation SHALL assume an empty namespace and count the bytes the archive produces, not what the sink stores; duplicates SHALL follow `SinkOptions::skip_duplicates` (default true) exactly as the path-based API | must |
| FR-015 | A sink error SHALL end the extraction as `ArchiveError::Io` when no entry was delivered and as `PartialExtraction` wrapping it afterwards; an `io::ErrorKind::QuotaExceeded` error carrying `SinkFull` SHALL map to `QuotaExceeded { resource: SinkCapacity { max } }` | must |
| FR-016 | `SinkOptions` (`#[non_exhaustive]`, Copy) SHALL carry `skip_duplicates` and `decode_reuse: DecodeReuse` (default `Off`, set through `with_decode_reuse`; #890, #946); `SinkOptions::try_from(&ExtractionOptions)` SHALL carry only the duplicate policy and set `decode_reuse` to `Off`, and SHALL fail with `InvalidConfiguration` when `atomic` is set, since atomic extraction renames a directory (#794, #808) | must |
| FR-017 | Symlinks SHALL be delivered on every platform, including hosts where the path-based API refuses to create them; a hardlink to a directory SHALL be `InvalidArchive`; a directory or file entry through a dangling symlink, or over a file or symlink, SHALL be refused with the same entry-naming message as `extract` and `verify` (#802, #803) | must |
| FR-018 | For a 7z source the file-table checks (admission, ratios, quotas, link policy, paths, name lengths for the sink's `PathModel`) SHALL run and refuse before any block is decoded or any entry is delivered (#772, #785) | must |
| FR-019 | The in-memory destination model SHALL charge each distinct name against a node budget of `max_file_count * max_path_depth + 1`; exhausting it SHALL fail with `QuotaExceeded { resource: TreeNodes { max } }`; a link path that leaves the root and returns SHALL be refused as an escape | must |

### 3.3 Path Model

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | `PathModel` (`#[non_exhaustive]`, default `Host`) SHALL select the path semantics a destination is validated against: `Host` applies the running platform's rules, `Portable` applies the strictest rules of every supported platform on every host | must |
| FR-021 | `Portable` SHALL fold names as macOS does, refuse components with a backslash, `<>"\|?*`, a control character, `:`, a trailing dot or space, a reserved Windows device name (unless `windows_reserved_names` is allowed) or bytes that are not UTF-8, limit components to 255 and paths and symlink targets to 1023 (UTF-8 bytes and UTF-16 units alike), and cut symlink chains after 32 hops | must |
| FR-022 | On a Windows host `PathModel::Host` SHALL apply the `Portable` component rules (`<>"\|?*`, control characters, `:`, trailing dot or space, non-Unicode text), refusing such entry names and link targets as `SecurityViolation`, including for in-memory Host sinks; on other hosts `Host` places no component restriction (#780, #790) | must |

### 3.4 Memory Sink

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `MemorySink` SHALL collect entries as `MemoryEntry::{File { data, mode }, Directory, Symlink { target }}` in a path-ordered map, bounded by a `MemoryLimit` that counts payload bytes (file data, hardlink copies, symlink targets), path bytes and `MemorySink::ENTRY_OVERHEAD` (256) per entry; exceeding it SHALL return the `SinkFull` error | must |
| FR-031 | `MemoryLimit` SHALL wrap a `NonZeroU64`, offer `DEFAULT` (500 MiB) and `from_config` (the config's `max_total_size`, zero becoming one byte), so a zero limit is unrepresentable | must |
| FR-032 | `MemorySink::with_path_model` SHALL select the model; accessors SHALL be `get`, `iter`, `into_entries`, `limit` and `stored_bytes` | must |
| FR-033 | `extract_reader_to_memory(reader, &MemoryExtractRequest, progress)` SHALL extract the archive in an `ArchiveReader` (built with `ArchiveReader::from_bytes` for bytes) into a `MemorySink` (limit defaulting to `MemoryLimit::from_config`) and convert a partial failure to `PartialWrites::Discarded` | must |
| FR-034 | Language bindings that expose entry paths as strings SHALL fail with `InvalidArchive` ("entry path is not valid UTF-8: ...") for a path that is not UTF-8, each with a private check | should |

### 3.5 Writer

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | `ArchiveWriter` SHALL wrap a `Write + Send` destination for TAR (optional codec) or a `Write + Seek + Send` destination for ZIP; `of_type(writer, CreatableFormat)` SHALL be infallible and `format()` SHALL report the `CreatableFormat` | must |
| FR-041 | `CreatableFormat` (`#[non_exhaustive]`: `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`) SHALL be the subset of `ArchiveType` that can be created, with `From<CreatableFormat> for ArchiveType` and a fallible reverse conversion (7z fails); `CreationConfig::format` was removed and the format is stated on `OutputFile::with_format` or by `CreateRequest::to_bytes(CreatableFormat, ..)` (#794, #808, #915) | must |
| FR-042 | `CreateRequest::write(ArchiveWriter, sources)` SHALL create an archive into the writer; on error the writer may hold a partial archive and the caller owns it | must |
| FR-043 | `CreateRequest::to_bytes(CreatableFormat, sources)` SHALL return `(Vec<u8>, CreationReport)` with `bytes_compressed` equal to the byte length | must |
| FR-044 | `create_archive`, `CreateRequest::{create, to_bytes}` and the Python and Node `create_archive_to_bytes` SHALL, for a ZIP result, add a report warning when default extraction would refuse an entry as a zip bomb, giving the number of entries and the smallest `max_compression_ratio` that admits them; a failure to read the finished ZIP back SHALL be a warning, not an error. `CreateRequest::write` over a writer that cannot be read back SHALL NOT scan; `create` reads the staged file back before publishing it (#801, #931) | should |

### 3.6 Extract Targets

| ID | Requirement | Priority |
|----|------------|----------|
| FR-050 | TAR, ZIP and 7z handlers SHALL keep every per-format gate in their own loop and send only validation and the final write through the `ExtractTarget` trait (`HostTarget` for the filesystem, `SinkTarget` for an `EntrySink`), so both destinations run the same gates | must |
| FR-051 | `ExtractTarget` SHALL admit each entry kind through a typed per-kind result built by `ValidatorCore` (`security::admitted`: `ValidatedFile` with its `QuotaPermit`, `ValidatedSymlink`, `ValidatedHardlink`, `EntrySize` with private fields) rather than one shared untyped entry, and a skipped duplicate SHALL be a `FileAdmission::Skipped(DuplicateSkipped)` token the target obtains only by counting the skip (#793, #808) | must |
| FR-052 | 7z SHALL use one extraction loop (`formats::sevenz::extract`) for both destinations, with `SevenZHostTarget` (re-validates every parent, temp-file-and-rename over an existing regular file) and the sink target differing only in their `SevenZTarget` hooks (#792, #808) | must |

### 3.7 Progress

| ID | Requirement | Priority |
|----|------------|----------|
| FR-060 | `ListRequest`, `VerifyRequest`, `SinkExtractRequest` and `CreateRequest` with `with_progress` SHALL report per-entry progress through `ProgressCallback`; the contract is specified in [[004-progress-tracking/spec]] (#782, #787, #790) | must |

### 3.8 Platform

| ID | Requirement | Priority |
|----|------------|----------|
| FR-070 | `exarch-core` SHALL compile for `wasm32-wasip1`, and `exarch-cli` SHALL build for it and pass a wasmtime smoke test in the CI job `wasm` (`cargo check -p exarch-core --all-features --target wasm32-wasip1`, `cargo build -p exarch-cli --target wasm32-wasip1`, `.github/scripts/wasi-smoke.sh`); the static `liblzma` build needs WASI libc headers and `llvm-ar` on the runner (#755, #771) | must |

### 3.9 Bindings

| ID | Requirement | Priority |
|----|------------|----------|
| FR-080 | Python SHALL expose `list_archive_bytes`, `verify_archive_bytes`, `extract_archive_to_memory`, their `_with_progress` variants (list, verify, extract) and `create_archive_to_bytes`; Node SHALL expose the same as `listArchiveBytes`, `verifyArchiveBytes`, `extractArchiveToMemory`, `listArchiveBytesWithProgress`, `verifyArchiveBytesWithProgress`, `extractArchiveToMemoryWithProgress` and `createArchiveToBytes`, each Node function with a `Sync` counterpart except the progress variants (#776, #784, #783, #787, #790) | must |
| FR-081 | The extract-to-memory functions SHALL take `data`, `config`, `options` (a `SinkOptions` class; `atomic` cannot be requested, #926), `max_bytes`/`maxBytes` (positive whole number, default the config's `max_total_size`), `path_model`/`pathModel` (`host` default or `portable`) and an optional `format`, and return the report with entries as per-kind types (Python `MemoryFile`, `MemoryDirectory`, `MemorySymlink`, `MemoryHardlink`; Node a union discriminated by `kind`; #923); the format is detected from the leading bytes when omitted | must |
| FR-082 | `create_archive_to_bytes`/`createArchiveToBytes` SHALL take sources, a format (`SevenZ` fails with `INVALID_CONFIGURATION`/`ValueError`) and an optional `CreationConfig`, and return the bytes and the `CreationReport`; the archive is held in memory (about 2-3x its size at the peak) with no cap | must |
| FR-083 | A failed in-memory extraction that had already collected an entry SHALL carry `writes == "discarded"` and no counters; a progress callback that throws after a successful in-memory extraction SHALL discard the entries and carry `writes == "discarded"` and the callback error | must |

### 3.10 Callback Delivery

| ID | Requirement | Priority |
|----|------------|----------|
| FR-090 | `CallbackSink<F>` SHALL be an `EntrySink` that hands each verified entry to a closure `FnMut(&SafePath, CallbackEntry) -> io::Result<()>` after all of a file's bytes were written and the stream delivered exactly the declared size; the memory held is one file (bounded by `max_file_size`) and the sink keeps nothing, and `with_path_model` selects the model (v0.8.0, #842, #859, #884) | must |
| FR-091 | `CallbackEntry` (`#[non_exhaustive]`) SHALL be `Stored(MemoryEntry)` for a file, directory or symlink, or `Hardlink { target: SafePath }` carrying the validated, root-relative path of an entry already delivered (a file or an earlier hardlink), so `MemoryEntry::Hardlink` is removed and `MemorySink::into_entries` cannot hold a hardlink; a hardlink is delivered after every other entry and its bytes stay charged to the quota (v0.8.0, #842, #859, #884) | must |
| FR-092 | Entries delivered to a callback are provisional: a later refusal or a stream-level failure (the gzip trailer CRC of a `.tar.gz` is checked after the end-of-archive marker) SHALL end the extraction with an error after earlier entries were delivered, so a caller treats them as final only once the call returned `Ok` (v0.8.0, #842, #848) | must |
| FR-093 | `extract_reader_to_callback(reader, &MemoryExtractRequest, on_entry, progress)` SHALL extract through a `CallbackSink` with the config, options and path model of the request (its memory limit is ignored), and return `Result<ExtractionReport, CallbackError<E>>` where `CallbackError::Callback(E)` holds the first error of `on_entry`, taking precedence over the archive error the aborted extraction reports, and `CallbackError::Archive(ArchiveError)` any other failure; `CallbackError` is exhaustive (closed by design, #922: bindings match it without a wildcard arm), shows `entry callback failed` and chains to the callback error through `source()` (v0.8.0, #842, #860, #884) | must |
| FR-094 | Python `extract_archive_to_callback(data, on_entry, config, options, path_model, format)` SHALL deliver each entry to a callable and re-raise its exception unchanged; Node `extractArchiveToCallback` (async) and `extractArchiveToCallbackSync` SHALL take `data`, `onEntry`, `config`, `options`, `pathModel`, `format` and, for the async form, `signal`; the async form SHALL accept an `AsyncIterable<Uint8Array>` for TAR and `onEntry` MAY return a promise, while the sync form SHALL fail with `TypeError` for a promise (v0.8.0, #842, #860, #884) | must |
| FR-095 | Node async functions that take an `AsyncIterable` SHALL accept an optional trailing `signal` (`AbortSignalLike`): aborting rejects with `ABORT_ERR` (an `AbortError`, `cause` is `signal.reason`) and frees the blocking worker, also for a pending `onEntry` promise or a stalled iterable; the abort is noticed at each read of a `Uint8Array` archive and each progress callback; an `onEntry` throw or rejection SHALL reject with `ENTRY_CALLBACK_ERROR` carrying the thrown value as `cause`, an iterable that throws with `STREAM_ERROR`, and an abort raised from `onEntry` keeps the `signal.reason` (v0.8.0, #842, #848, #856, #860, #884) | must |
| FR-096 | `EntrySink` SHALL provide `create_file_from`, and `MemorySink::new` SHALL NOT be `const` (v0.8.0, #866, #894) | must |
| FR-097 | `ArchiveReader::of_stream(reader, ArchiveType)` SHALL open a non-seekable TAR stream of the stated format and fail with `ReaderFormat(NeedsSeek)` for ZIP or 7z (v0.8.0, #828, #884) | must |

### 3.11 Listing for Extraction

| ID | Requirement | Priority |
|----|------------|----------|
| FR-100 | `ListRequest::for_extraction(path, DecodeReuse)` (taking the extraction `SecurityConfig` and the `ListOptions`) SHALL return a `ListedArchive` whose `manifest()` is the list result and whose `extract(output_dir, &ListedExtractOptions { atomic, skip_duplicates }, progress)` extracts the listed archive under the stored extraction config (the list pass runs under `SecurityConfig::for_listing()`; `extract_under` and `list_archive_for_extraction` were removed, #901, #912), so a caller that must inspect an archive before extracting it (conflict check, progress total) does not pay a second decode (v0.8.0, #828, #884) | must |
| FR-101 | For a gz, bz2 or xz TAR the list pass SHALL spool the decoder output to an unnamed temporary file up to 256 MiB, and `extract` SHALL read the spool instead of decoding again; plain TAR and zstd TAR (a codec that decodes faster than a disk round trip) SHALL keep nothing | must |
| FR-102 | `extract` SHALL decode again, exactly as without a listing, whenever the spool cannot be trusted to equal a fresh decode: the decoder failed or did not reach its end, the decoded stream exceeds the limit or a spool write failed, or (until #901) the extraction's `max_decoder_memory` was below the one the list pass decoded under — since #901 the extraction runs under the config the `ListedArchive` stores, a mismatch is unrepresentable and `Kept::serves` is a `debug_assert!`; a fallback is chosen by size and contents, never as a security property, and extraction validates every entry again; a read error during the replay SHALL be `Io` with its errno (v0.8.0, #828, #882, #884) | must |
| FR-103 | For a ZIP the `ListedArchive` SHALL keep the parsed archive open and reuse the deflate output of the structure check per `DecodeReuse` (see [[003-config-api/spec]]): `Off` keeps nothing, `Memory(ReuseLimit)` keeps decoded entries in memory up to the limit, `TempFile(ReuseLimit)` in an unnamed temporary file (nothing is kept on WASI or when none can be created; a spool on a Linux tmpfs or ramfs is charged like `Memory`, see [[002-format-handlers/spec]] FR-061; the TAR spool of the `ListedArchive` is still uncharged); `ReuseLimit` is at most 256 MiB, kept output is clamped to `max_decoder_memory` and `max_total_size`, and entries over `max_file_size` or `max_compression_ratio` are not kept; the library default is `Memory(32 MiB)` and the CLI `extract --decode-reuse <off\|memory\|temp-file>` defaults to memory up to 256 MiB; bzip2 and zstd output of the check are kept as well, and `extract_reader_to_memory` always reuses in memory (v0.8.0, #857, #866, #884, #894) | must |
| FR-104 | `exarch extract` into an existing destination SHALL decode a gz, bz2 or xz TAR once, and `exarch extract --atomic` SHALL decode a TAR once, so a refusal arrives as a `rolled_back` partial report instead of a pre-write error and the progress bar has no total (v0.8.0, #828, #842) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | A sink or reader path SHALL NOT weaken any gate of the path-based API; every difference is stricter and fails closed (hardlink to a directory, escape-and-return links, dangling-symlink parents) |
| NFR-002 | Resource bounds | Validation memory is bounded by the node budget (about 550 bytes plus 1.6 bytes per name byte per name, measured: 320000 directory entries peaked at 176 to 223 MB resident); `MemoryLimit` does not count this overhead |
| NFR-003 | Type safety | A zero `MemoryLimit`, an uncreatable writer format, a sink option that needs a directory and an unvalidated file admission SHALL be unrepresentable or rejected at construction, not checked per call |
| NFR-004 | Portability | The reader, sink and writer APIs need no filesystem; the crate builds for `wasm32-wasip1` |
| NFR-005 | Layering | Bindings only convert types and bytes; all validation stays in `exarch-core` |
| NFR-006 | Resource bounds | A ZIP extraction through `extract_reader_to_callback` or a custom `EntrySink` runs in O(buffer) memory by default (each deflate entry is decoded twice); `SinkOptions::decode_reuse` is opt-in: `DecodeReuse::Memory` holds up to its caller-supplied `ReuseLimit` on the heap (the limit counts only the store, not the delivered entry or the sink's own copy), `DecodeReuse::TempFile` writes the archive plaintext to the platform temporary directory (possibly RAM on a tmpfs) until the extraction ends, and an entry above the limit is still decoded twice; `extract_reader_to_memory` always reuses in memory within its own limit and ignores the field (#890, #946; temp-file cost follow-up #929) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ArchiveReader<'a>` | Archive supplied as a reader | `tar`, `seekable`, `of_type`, `from_bytes`, `detect`, `detect_stream`, `format` |
| `SeekableFormat` | `#[non_exhaustive]` formats needing `Seek` | `Zip`, `SevenZ`; `as_str()` |
| `ReaderFormatError` | `#[non_exhaustive]` reader format failures | `Unrecognized`, `NeedsSeek(SeekableFormat)`, `NotAtStart(SeekableFormat)` |
| `EntrySink` | Receiver of validated entries | `File: Write`, `path_model`, `create_directory`, `create_file`, `finish_file`, `create_symlink`, `create_hardlink` |
| `SinkOptions` | Duplicate policy and ZIP decode reuse of a sink run | `skip_duplicates` (default true), `decode_reuse` (default `DecodeReuse::Off`) |
| `SinkFull` | Payload of a sink's `QuotaExceeded` error | `new(max)`, `max()` |
| `MemorySink` / `MemoryLimit` / `MemoryEntry` / `MemoryEntryKind` / `MemoryFile` | In-memory sink and its parts | see FR-030 to FR-032 |
| `PathModel` | Path semantics of a destination | `Host`, `Portable`; `as_str()` |
| `ArchiveWriter<'a>` / `CreatableFormat` | Archive destination and creatable formats | `tar`, `zip`, `of_type`, `format` |
| `QuotaResource::{TreeNodes, SinkCapacity}` | Quota resources added with this API | `max` |
| `ExtractTarget` / `HostTarget` / `SinkTarget` | Validation-and-write half of an extraction | per-kind `validate_*`, `directory`, `file`, `symlink`, `hardlink` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| ZIP or 7z in a forward-only reader | `ReaderFormat(NeedsSeek)` from `detect_stream` |
| ZIP or 7z signature at a nonzero reader position | `ReaderFormat(NotAtStart)` |
| v7 TAR (no `ustar` marker) or a ZIP with data prepended | Not recognized by `detect`; use `ArchiveReader::tar` or an offset-mapping reader |
| Sink returns an error before any entry is delivered | `ArchiveError::Io` |
| Sink returns an error after an entry was delivered | `PartialExtraction` wrapping `Io`, `writes` per the caller (`Discarded` for in-memory) |
| Sink returns `QuotaExceeded` with `SinkFull` | `QuotaExceeded { resource: SinkCapacity { max } }` |
| Names that differ only by case on a case-folding model | One name; the delivered path is the spelling stored first |
| Sink on a host where symlinks are refused by the path-based API | Symlink still delivered |
| `ExtractionOptions` with `atomic` converted to `SinkOptions` | `InvalidConfiguration` |
| `max_bytes` of zero, negative or fractional in a binding | `INVALID_CONFIGURATION` / `ValueError` |
| `create_archive_to_bytes` with a FIFO or device source | Not supported |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Sink extraction versus path-based extraction on the same archives | The differential test (`tests/sink_differential.rs`) passes; the only differences are the documented stricter ones |
| SC-002 | Reader detection and sink path model under hostile input | `detect` and `sink` fuzz targets exist in `fuzz/` (#798, #808) |
| SC-003 | WASI build | CI job `wasm` passes the wasmtime smoke test |
| SC-004 | Memory use of an in-memory extraction | Stored bytes never exceed the `MemoryLimit` |

## 8. Agent Boundaries

### Always (without asking)
- Route every sink and reader operation through the same validator and gates as the path-based API
- Keep new per-format gates in the format loop, not in a target
- Update the Python stub, `index.d.ts` and the `exarch-cli` skill when the in-memory binding surface changes

### Ask First
- Adding a method to `EntrySink` or `ExtractTarget` (breaking for implementors)
- Adding a `PathModel` variant

### Never
- Let a sink observe an unvalidated path or an unreserved file size
- Publish data from a `File`'s `Drop` or `write`
- Make `extract_to_sink` accept `atomic`

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `list_reader`/`verify_reader` accept a forward-only ZIP via the local headers, given the central directory is the authority exarch validates?]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — path model, typed admission and the validator the sink reuses
- [[002-format-handlers/spec]] — format handlers and detection
- [[003-config-api/spec]] — `SinkOptions`, `CreationConfig::format`
- [[004-progress-tracking/spec]] — progress contract for the new variants
- [[019-verify-and-list-model/spec]] — the in-memory tree used by `verify` and the sink
- [[006-python-bindings/spec]] and [[007-node-bindings/spec]] — in-memory functions
- `crates/exarch-core/src/reader.rs`, `sink.rs`, `sink/memory.rs`, `writer.rs`, `formats/target.rs`, `formats/sevenz/extract.rs`
