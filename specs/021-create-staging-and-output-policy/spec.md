---
aliases:
  - Create Staging and Output Policy
  - Atomic Archive Creation
  - OutputFile and OutputPolicy
tags:
  - sdd
  - spec
  - creation
  - security
  - rust
created: 2026-11-04
updated: 2026-11-04
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Create Staging and Output Policy

> [!info] Metadata
> **Subsystem**: exarch-core / `request` (`OutputFile`, `OutputPolicy`, `OutputFormat`, `CreateRequest`), `creation::staged`, `creation::filters`, `creation::walker`
> **MSRV**: Rust 1.98.0
> **Origin**: #931 (staged output), #915 (format moved off `CreationConfig`), #916 (typed exclude patterns) — 50-issue batch, 2026-11-04
> **Status**: implemented — documents the behavior that shipped in that batch

## 1. Overview

### Problem Statement

`create_archive` wrote straight into the output path. A creation that failed
halfway (a missing source, a refused entry, a full disk) left an empty or
truncated archive at the path, and with `--force` the previous archive had
already been removed. The CLI protected itself with an `exists()` check and a
`remove_file` before the work started, a check that raced with other writers and
that bindings did not have at all. A source directory that contained the output
(`create out.tar.gz .`) archived the output into itself. The archive format
lived on `CreationConfig`, so a config could contradict the extension of the
file it was used for. Exclude patterns were bare strings matched against the
absolute source path, so `-x '*.tmp'` produced an empty archive whenever the
source sat under a directory that matched.

### Goal

Creating an archive is all-or-nothing at the output path, the caller states
whether an existing file may be replaced, the format belongs to the output
rather than to the config, and exclude patterns are typed, validated and matched
against the entry name the user sees in `list`.

### Out of Scope

- Atomic replace of an extraction destination (see [[015-atomic-force-destination-swap-hardening/spec]])
- Preserving owner, ACLs or extended attributes of a replaced archive
- Writing to a FIFO, a device or `/dev/stdout` (use `CreateRequest::write` with a writer)
- `fsync` of the parent directory after the rename

## 2. User Stories

### US-001: A failed creation leaves the output untouched

AS A script author
I WANT a failed `exarch create out.tar.gz ./src` to leave `out.tar.gz` exactly as it was
SO THAT a retry loop or a backup job never destroys the last good archive

**Acceptance criteria:**
```
GIVEN out.tar.gz holds a previous archive and a source path that does not exist
WHEN create runs with --force
THEN it fails, out.tar.gz is byte-identical to before, and no temporary file remains beside it
```

```
GIVEN out.tar.gz does not exist and creation fails
WHEN create runs
THEN out.tar.gz still does not exist
```

### US-002: The caller states whether to replace

AS A library user
I WANT `OutputFile::create_new(path)` and `OutputFile::replace(path)` with no default
SO THAT overwriting a file is always a visible decision

**Acceptance criteria:**
```
GIVEN a regular file at the path
WHEN CreateRequest::create is called with OutputFile::create_new
THEN the result is ArchiveError::OutputExists and the file is unchanged
```

```
GIVEN a regular file with mode 0o640 at the path
WHEN CreateRequest::create is called with OutputFile::replace
THEN the new archive replaces it atomically and has mode 0o640
```

### US-003: The archive never contains itself

AS A developer
I WANT `create out.tar.gz .` to skip `out.tar.gz` and its staged temporary file
SO THAT an archive is not recursively included in itself

**Acceptance criteria:**
```
GIVEN a source directory that contains the output path (new or replaced)
WHEN create runs
THEN neither the target nor the staged file appears among the archive entries
```

### US-004: Format follows the output, explicitly when needed

AS A packager
I WANT `OutputFile::with_format(CreatableFormat::Zip)` for a `.apk`, `.whl` or `.epub` name
SO THAT I can write a plain ZIP under an extension exarch refuses to guess

**Acceptance criteria:**
```
GIVEN OutputFile::replace("app.apk") without an explicit format
WHEN create runs
THEN it is refused as a ZIP-family extension exarch does not produce
```

```
GIVEN OutputFile::create_new("app.apk").with_format(CreatableFormat::Zip)
WHEN create runs
THEN a plain ZIP is written
```

### US-005: Exclude patterns that cannot be honored are refused

AS A CLI user
I WANT `create -x 'build/*'` to fail instead of silently matching nothing
SO THAT a typo in a pattern never ships files I meant to leave out

**Acceptance criteria:**
```
GIVEN -x '*.tmp' and a source tree whose root sits under a directory called x.tmp
WHEN create runs
THEN the archive contains the tree minus files whose archive path component ends in .tmp; it is not empty
```

```
GIVEN -x 'build/*'
WHEN create runs
THEN it fails with InvalidConfiguration (setting exclude_pattern), exit 1, and no archive is written
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `OutputPolicy` SHALL be `#[non_exhaustive]` with exactly `CreateNew` and `Replace`; there SHALL be no `Default` and no `bool` parameter standing for it | must |
| FR-002 | `OutputFile` SHALL be built only by `OutputFile::create_new(path)` and `OutputFile::replace(path)`, optionally followed by `with_format(CreatableFormat)`; accessors are `path()`, `policy()` and `format()` | must |
| FR-003 | `OutputFormat` SHALL be `#[non_exhaustive]` with `FromExtension` (default) and `Explicit(CreatableFormat)`; the ZIP-family extension refusal (`.apk`, `.whl`, `.epub`, ...) SHALL apply only to `FromExtension` | must |
| FR-004 | `CreationConfig::format` and `CreationConfig::with_format` SHALL NOT exist; `ArchiveCreator` SHALL NOT exist | must |
| FR-005 | WHEN `CreateRequest::create(&OutputFile, sources)` runs, THE SYSTEM SHALL write the archive to a temporary file (prefix `.exarch-`) in the canonical parent directory of the target and publish it by rename only after the archive is complete and `sync_all` succeeded | must |
| FR-006 | WHEN creation fails for any reason before the rename, THE SYSTEM SHALL delete the temporary file and leave the target path exactly as it was (absent, or holding the previous file) | must |
| FR-007 | Everything that can refuse the target SHALL be decided before any source is read: the target kind, `OutputExists`, the parent directory | must |
| FR-008 | The target kind SHALL be decided by `symlink_metadata(target)` (and `metadata(target)` for a symlink): absent is accepted by both policies; a regular file, a symlink to a regular file and a dangling symlink are accepted by `Replace` and refused by `CreateNew` with `ArchiveError::OutputExists`; anything else (directory, FIFO, device, symlink to a non-regular file) SHALL be refused by both policies with `InvalidConfiguration { setting: OutputPath, problem: NotSupported }`, which takes precedence over `OutputExists` | must |
| FR-009 | WHEN `Replace` replaces a regular file (or a symlink that resolves to one), THE staged file SHALL get the replaced file's `mode & 0o777` (never setuid, setgid or sticky, never wider than before), applied after the write and `sync_all`, right before the rename; the staged file SHALL be `0o600` while it is written | must |
| FR-010 | WHEN the target is absent or a dangling symlink, THE staged file SHALL get `0o666` filtered by the umask, like `File::create` | must |
| FR-011 | WHEN the target is a symlink under `Replace`, THE SYSTEM SHALL replace the link itself, not its destination | must |
| FR-012 | `Replace` SHALL NOT preserve owner, ACLs or extended attributes of the replaced file; the doc comment SHALL say so | must |
| FR-013 | `CreateNew` SHALL publish with `persist_noclobber`; a file that appeared between staging and publishing SHALL yield `OutputExists` with the file untouched | must |
| FR-014 | WHEN `persist_noclobber` fails for a reason other than "already exists" (the hard-link primitive is missing on FAT and exFAT), THE SYSTEM SHALL reserve the name with `File::create_new` and rename the staged file over the reservation; a failed rename SHALL remove the reservation only after its identity (device and inode on Unix) is confirmed, and otherwise SHALL leave it and name it in the error | must |
| FR-015 | The walker SHALL exclude the staged file and the target from the archive by path, before the hidden-file filter and without counting them as skips (a staged `.exarch-*` file is hidden, and must not appear as a `Hidden` skip): the entry's file name is compared first, then its canonical parent; file identity SHALL NOT be used because it is not stable on Windows. The name comparison is case-sensitive | must |
| FR-016 | `create_archive(path, sources, config)` SHALL mean `OutputFile::replace(path)` with `FromExtension` | must |
| FR-017 | `CreateRequest::write(ArchiveWriter, sources)` and `CreateRequest::to_bytes(CreatableFormat, sources)` SHALL be unaffected by staging; `CreationReport::bytes_compressed` for `create` SHALL be the size of the published file | must |
| FR-018 | WHEN `create` writes a ZIP, THE SYSTEM SHALL read the staged file back to compute the extraction-ratio warning (`CreationWarning::ZipRatioOverDefaultLimit` / `ZipRatioCheckFailed`) before the rename | should |
| FR-019 | `ExcludePattern` SHALL be a `#[non_exhaustive]` enum with variants `Exact { name }`, `Prefix { prefix }` (`name*`), `Suffix { suffix }` (`*name`) and `Path { relative }`; the variants are themselves `#[non_exhaustive]`, so values are built only by `TryFrom<&str>` / `FromStr` and printed by a round-tripping `Display` | must |
| FR-020 | A pattern without a separator and without `*` SHALL be `Exact`; one with a single leading or trailing `*` SHALL be `Suffix` or `Prefix`; one with a separator and no `*` SHALL be `Path`, anchored at the archive root, matching that relative path and its subtree. A bare name matches one path component at any depth | must |
| FR-021 | THE SYSTEM SHALL refuse with `InvalidConfiguration { setting: ExcludePattern, problem: ExcludePatternRefused { pattern, reason } }`, where `reason` is an `ExcludeRefusal` (`empty`, `too_long`, `contains_nul`, `dot_entry`, `absolute`, `unsupported_wildcard`, `wildcard_with_separator`, `glob_metacharacter`, `padded_with_blank`, `contains_comma`) and the message names the pattern: an empty pattern, a NUL byte, a pattern over 255 bytes, `.` or `..`, an absolute path, a bare `*`, an inner or double `*`, a separator combined with `*` (e.g. `build/*`, `a*b`), any of `?`, `[`, `]`, `{`, `}` and `!` (glob look-alikes that would be matched literally), a comma (it reads as a list separator), and leading or trailing whitespace or control characters | must |
| FR-022 | Patterns SHALL match the archive entry path (after `strip_prefix` and multi-source naming), the name shown by `list`, and SHALL NOT match the ancestors of the source root | must |
| FR-023 | `CreationConfig::exclude_patterns` SHALL be `Vec<ExcludePattern>`; `with_exclude_patterns` takes `Vec<ExcludePattern>`; there SHALL be no unparsed-string setter, so a refused shape cannot be stored | must |
| FR-024 | Matching SHALL compare raw bytes of path components (`OsStr::as_encoded_bytes`), so a non-UTF-8 name is matched, not skipped or lossily converted. Entries dropped by an exclude pattern or by the hidden-file rule SHALL be counted in `CreationReport::skipped` as `SkipKind::Excluded` and `SkipKind::Hidden`; the other creation skips are `OverMaxFileSize` and `SymlinkUnsupported` | must |
| FR-025 | `CreateRequest` SHALL document `# Errors` once; `ArchiveCreator`, `FormatCreator`, `TarCreator`, `ZipCreator` and the public `creation::{tar,zip}::create_*` SHALL NOT exist; creation SHALL dispatch by `CreationFamily` | must |
| FR-026 | WITH `include_hidden = false`, THE walker SHALL NOT enter a hidden directory below a source root and SHALL count it once as `SkipKind::Hidden`; hidden is decided on the raw name bytes (a leading `.`); a hidden source root named by the caller, a file source and `include_hidden = true` SHALL be unchanged; with `follow_symlinks` the visible name of a link decides whether it is hidden, not its target's (BREAKING: contents of hidden directories that were previously archived and then filtered are no longer read) | must |

### Surfaces

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | THE CLI `create` SHALL map `--force` to `OutputFile::replace` and its absence to `OutputFile::create_new`; it SHALL NOT call `exists()` or `remove_file`; `OutputExists` SHALL carry a hint naming `--force`; a directory, FIFO or device output SHALL be an `InvalidConfiguration` for `output_path` with and without `--force` | must |
| FR-041 | THE CLI `create -x` SHALL parse patterns with `ExcludePattern::try_from` after clap; a refused shape SHALL exit 1 with the JSON envelope (`setting: exclude_pattern`) and write no archive; the `-x` help text SHALL name the shapes | must |
| FR-042 | Python `create_archive` and `create_archive_with_progress` SHALL take `format: str | None` and `overwrite: bool = True`; `overwrite=False` maps to `create_new` and raises `OutputExistsError` (a `FileExistsError`); a refused exclude pattern SHALL raise `InvalidConfigurationError` with `setting == "exclude_pattern"`; a progress callback that raises SHALL cancel the creation (nothing is committed, a previous archive stays) | must |
| FR-043 | Node `createArchive*` SHALL replace an existing output atomically (`OutputFile::replace`); it takes an optional trailing `CreateOptions { format?: ArchiveType, overwrite?: boolean }` (default replace; `overwrite: false` maps to `create_new`, `format` to `OutputFile::with_format`, `'SevenZ'` is refused); `addExcludePattern` SHALL throw `INVALID_CONFIGURATION` with `setting: 'exclude_pattern'` for a refused shape | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | No creation outcome leaves a partial archive at the target; the only residue is the documented FAT/exFAT reservation window (FR-014) |
| NFR-002 | Security | The staged file is never wider than `0o600` while written when it will replace a file; a replaced file's mode is never widened and never gains setuid, setgid or sticky bits |
| NFR-003 | Compatibility | BREAKING: the parent directory of the output must be writable, and the output is replaced by rename (a hard link to the old file no longer sees the new content) |
| NFR-004 | Performance | `commit` fsyncs every created archive (`sync_all`) and then, best effort, its parent directory; creation of many small archives pays a fixed cost of about 4 to 10 ms each (measured) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `OutputPolicy` | Whether an existing file may be replaced | `CreateNew`, `Replace` |
| `OutputFormat` | How the archive format is chosen | `FromExtension`, `Explicit(CreatableFormat)` |
| `OutputFile` | The archive file a creation writes | `create_new`, `replace`, `with_format`, `path`, `policy`, `format` |
| `StagedOutput` | Crate-private temporary file next to the target; deleted on drop | `begin(target, policy)`, `parts()`, `commit()` |
| `ExcludedOutput` | Crate-private pair of names (target, staged file) plus the canonical parent that the walker must skip | `excludes(path)` |
| `ExcludePattern` | Parsed exclude pattern | `Exact`, `Prefix`, `Suffix`, `Path`; `matches(&Path)`; `skip_reason(archive_path, config)` |
| `CreateRequest<'a>` | Creation under a `CreationConfig` with optional progress | `with_progress`, `create(&OutputFile, sources)`, `write(ArchiveWriter, sources)`, `to_bytes(CreatableFormat, sources)` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Source does not exist | Fails before publishing; target unchanged; no temporary file |
| Target is a directory, FIFO, device or `/dev/stdout` | `InvalidConfiguration { OutputPath, NotSupported }` for both policies, before any work |
| Target is a directory and policy is `CreateNew` | Same `InvalidConfiguration`, not `OutputExists` |
| `CreateNew` and a file appears after staging | `OutputExists`; the raced file is untouched; temporary file deleted |
| Target path has no parent component or a missing parent | `InvalidConfiguration { OutputPath, NoParent }` or an I/O error from resolving the parent |
| Output sits inside a source directory | Target and staged file skipped by path (FR-015) |
| Output spelled in another case than its on-disk name on a case-insensitive filesystem | Not recognized by the name comparison; the old archive can be archived into the new one |
| FAT or exFAT output with `CreateNew` | Reserve-then-rename fallback (FR-014); a crash between the two steps leaves an empty file at the target |
| `Replace` over a symlink to a regular file | The link itself is replaced; the mode comes from the file it pointed to |
| `Replace` of a read-only file | The new archive carries the read-only mode (set after the write); the rename still succeeds when the directory is writable |
| A hidden directory below a source root (`.git`, `.ssh`) without `include_hidden` | Never entered; one `hidden` skip for the directory, so a large hidden tree costs nothing (faster than walking and filtering it) |
| A hidden source root named by the caller, a file source, or `include_hidden = true` | Unchanged: archived |
| `--follow-symlinks` and a link `keys -> .ssh` | The visible name of the link decides: archived |
| Pattern `target/` or `src/gen` | `Path`, anchored at the archive root |
| Pattern `*.{a,b}`, `file?.txt`, `[ab]`, `!x`, `a,b` or `" a"` | Refused (`glob_metacharacter`, `contains_comma`, `padded_with_blank`); the message names the pattern |
| A non-UTF-8 file name and a pattern | Matched by raw bytes |
| The progress callback raises (or throws) during creation | Creation stops with `Interrupted`, the staged file is deleted and the previous archive is kept (Python and Node surface the callback's exception) |
| Pattern `*.tmp` and a source root under `x.tmp/` | Ancestors are not matched; the archive is not empty |
| Single-file top-level source matching an exclude pattern | Not filtered (unchanged behavior) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Failed creation leaves the target path byte-identical | `tests/create_output.rs`, CLI and binding tests |
| SC-002 | Replaced file keeps its mode, stripped of setuid, setgid and sticky | Unix unit tests in `creation/staged.rs`, live CLI check |
| SC-003 | Every exclude shape the old matcher accepted is refused or matches the same files under a non-matching root | Legacy-equivalence tests in `creation/filters.rs` |
| SC-004 | Self-inclusion cannot loop | Python and CLI tests with the output inside the source directory |

## 8. Agent Boundaries

### Always (without asking)
- Decide target refusals in `StagedOutput::begin` before reading sources
- Keep `StagedOutput` crate-private; route creation through `CreateRequest::create`
- Compare excluded names by path, never by file identity

### Ask First
- Preserving owner, ACLs or xattrs of a replaced file
- Syncing the parent directory after the rename
- Adding an `OutputPolicy` variant (the enum is `#[non_exhaustive]`)

### Never
- Write the archive directly to the target path
- Add a `Default` for `OutputPolicy` or accept a `bool` for it
- Store an unparsed exclude string in `CreationConfig`
- Delete a reservation file without confirming its identity

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `ExcludedOutput` add a platform identity check (device and inode on Unix) as a second test for case-insensitive filesystems?]
- [NEEDS CLARIFICATION: Should Python `overwrite: bool` become a `Literal["replace", "create_new"]` to match `OutputPolicy`?]
- [NEEDS CLARIFICATION: Should `Skip.io_kind` get a stable string table in Python (Node has `IoKind`)?]

> [!question] Follow-up issues
> #949 (Windows/WASI link walk and `canonical_within`), #950 (Linux spool and tmpfs measurement), #951 (`from_utf8_lossy_owned`, needs MSRV 1.99), #952 (symlink-chain cost, about +22 percent on the 30 x 31 stress shape), #953 (Node sync create cancellation and fsync opt-out).

## 10. See Also

- [[constitution]] — project principles
- [[003-config-api/spec]] — `CreationConfig` after the typestate removal
- [[004-progress-tracking/spec]] — `CreationReport` skips and entry positions
- [[005-cli/spec]] — `create` flags and exit codes
- [[015-atomic-force-destination-swap-hardening/spec]] — the extraction-side swap
- [[020-reader-sink-and-in-memory-api/spec]] — `CreateRequest::write` and `to_bytes`
