---
aliases:
  - MotW Propagation
  - Download-Origin Mark Propagation
tags:
  - sdd
  - spec
  - security
  - extraction
  - platform
created: 2026-11-08
updated: 2026-11-10
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[022-extract-entry-selection/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: Download-Origin Mark Propagation (Mark-of-the-Web / Quarantine)

> [!info] Metadata
> **Issue**: #1026 (promoted from the research draft; numbered 026 so as not to collide with the Landlock draft 025)
> **Type**: security parity gap, opt-in
> **Status**: implemented (macOS verified live; Windows compiled and clippy-checked, never run, see Open Items and #1150)

## 1. Overview

### Problem Statement

An archive downloaded from the internet carries a download-origin mark on the archive file: the Windows `Zone.Identifier` alternate data stream (Mark-of-the-Web, MotW) or the macOS `com.apple.quarantine` extended attribute. SmartScreen, Office Protected View and Gatekeeper decide whether to warn from the mark on each file. Extraction that drops the mark launders the content. Windows Explorer and macOS Archive Utility propagate it; 7-Zip does so opt-in (`-snz`); bsdtar, cpython `tarfile`, node-tar and zip2 do not.

Extraction still ignores every attribute, ACL and stream stored inside an archive; this is deliberate and unchanged. Propagation originates only from the mark on the archive file itself.

### Goal

When the user opts in, every file exarch extracts from a file-backed, marked archive carries an equivalent mark on platforms that define one, and the report states what happened.

### Out of Scope

- Restoring any xattr, ACL or stream stored inside an archive.
- Creating a mark on an archive that has none.
- Marking output of `create_archive`, `list` or `verify`; acting on the mark in `verify`.
- A Linux mark (documented no-op).
- Carrying `ReferrerUrl` / `HostUrl` on Windows; per-file-type selection; a strict (abort on failure) mode.

## 2. User Stories

### US-001: Preserve SmartScreen and Gatekeeper protection
AS A Windows or macOS user extracting a downloaded archive
I WANT extracted files to inherit the archive's mark
SO THAT SmartScreen, Office Protected View and Gatekeeper still warn

```
GIVEN a marked archive file AND propagation is when_marked
WHEN it is extracted
THEN each extracted file carries an equivalent mark (macOS: a fresh per-file UUID, flags derived from the source)
```

### US-002: Typed, opt-in control
AS A library consumer (Rust, Python, Node.js)
I WANT a typed policy defaulting to `Never` and a report field for the outcome
SO THAT behavior is explicit and observable

### US-003: Machine-readable CLI outcome
AS A CLI user with automation
I WANT `--json` to carry the propagation state and counts
SO THAT scripts can assert protection was preserved

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `ExtractionOptions` (and `ListedExtractOptions`) SHALL carry a typed `MarkPropagation { Never, WhenMarked }` (`#[non_exhaustive]`, stable tokens `never` / `when_marked`) with the default `Never`; propagation is opt-in | must |
| FR-002 | Under `Never` the system SHALL NOT read the archive's mark and SHALL NOT write any mark; no `MarkRun` is built and no deferred create happens | must |
| FR-003 | Under `WhenMarked` and a marked, file-backed archive on macOS or Windows, the system SHALL write an equivalent mark to every file the run creates: regular files, hardlink copies, `--force` temporary siblings that replace a file, and 7z writers | must |
| FR-004 | An archive without a mark SHALL yield `MarkOutcome::Unmarked` and no writes | must |
| FR-005 | The source mark SHALL be read once, from the archive file's own open handle, never by re-opening the path; on the listed route (`ListRequest::for_extraction`) it is the list-time `Arc<File>` kept in `Kept::TarSpool` / `Kept::Zip`, so replacing the archive path after listing changes nothing | must |
| FR-006 | A mark SHALL be written only through the handle that created the output (`fsetxattr` on the descriptor on macOS, handle-relative stream creation on Windows through `pinned_dir`), never through a path string or a `file:stream` name | must |
| FR-007 | Under `WhenMarked` a file SHALL be created in deferred mode: created `0600`, content written, mark written, then the final mode applied through `PendingMode`; the final mode SHALL be applied even when the mark write fails, so a read-only entry (`0444`) is marked and ends `0444` | must |
| FR-008 | Windows: the mark is the `Zone.Identifier` stream carrying `ZoneId` only (rendered `[ZoneTransfer]\r\nZoneId=N\r\n`); `ReferrerUrl` and `HostUrl` are not copied; the source `ZoneId` is parsed from the first 4096 bytes (BOM and LF endings accepted; values 0 to 4 valid) | must |
| FR-009 | macOS: the mark is `com.apple.quarantine` rendered `flags;timestamp;exarch;UUID`; flags are the source value masked to `0x0007` (zero becomes `0001`), the timestamp is the source's (else now), the agent name is `exarch`, and the UUID is a fresh version 4 value per object, never a byte copy | must |
| FR-010 | A source mark that is present but unparsable, non-ASCII, or oversized (macOS value over 256 bytes, or Windows stream without a valid `ZoneId` in the first 4096 bytes) SHALL propagate the conservative mark (macOS flags `0001`, Windows `ZoneId=3`); `MarkOutcome::Unreadable` is reserved for a real I/O error while reading the mark, marks nothing, and the human output prints a warning; on Windows a source volume that does not support named streams (`GetVolumeInformationByHandleW` reports no `FILE_NAMED_STREAMS`) has no stream to read and reads as `Unmarked`, like a macOS volume that answers `ENOTSUP`, while a failure of that volume query is not taken for "no streams": the stream read decides and its error stays `Unreadable`, never `Unmarked` (#1150) | must |
| FR-011 | On Linux and any platform without a defined mark the outcome SHALL be `UnsupportedPlatform` with no read and no write | must |
| FR-012 | An in-memory or reader-backed source has no archive file and therefore nothing to propagate; no mark policy applies to the `*_bytes`, reader and sink entry points | must |
| FR-013 | A mark SHALL never be derived from archive content (entry names, PAX or xattr records, stream-like names): a TAR `com.apple.quarantine` PAX record is ignored | must |
| FR-014 | Symlinks SHALL NOT be marked and SHALL NOT be followed to mark their target; skipped entries are not counted | must |
| FR-015 | macOS SHALL also mark directories this run created, only those: never a pre-existing directory, the destination root or the `--atomic` staging root; Windows does not mark directories (deviation from the draft, which excluded directories everywhere; user-approved) | must |
| FR-016 | `--atomic` extraction SHALL publish files that already carry the mark; the marks survive the final rename and no promoted file lacks one | must |
| FR-017 | A failed mark write SHALL be counted in `failed`, SHALL NOT abort extraction and SHALL NOT be reported as marked; there is no strict mode (user decision) | must |
| FR-018 | `ExtractionReport::mark` SHALL be a typed `MarkOutcome` (`#[non_exhaustive]`): `NotRequested` (default), `UnsupportedPlatform`, `Unmarked`, `Unreadable`, `Propagated { marked: usize, failed: usize }`; `as_str`, `state`, `marked`, `failed`, `has_failures` and `is_incomplete` (an object missing its mark, or an `Unreadable` source mark) are provided; `MarkOutcome::state()` returns the closed enum `MarkState` (`not_requested`, `unsupported_platform`, `unmarked`, `unreadable`, `propagated`; `ClosedEnum` with `ALL` and `NAMES`, exported from the crate root), and `as_str` delegates to it, so the token set has one source (#1158); a `PartialExtraction` report carries the outcome too (`Partial` boxes its report) | must |
| FR-019 | The CLI SHALL provide `extract --mark-propagation <never\|when-marked>` (default `never`; an invalid value exits `2`); `--json` SHALL always carry `mark_propagation: {state, marked, failed}` where `state` is the `MarkState` token of the core outcome, without remapping (an unknown future state is passed through as its own token), and `marked` and `failed` appear only for `propagated`, also inside `partial_report`; text output SHALL print `Download mark: copied to N items, M failed` (or the reason nothing was copied) under `when-marked`, plus a warning line when the outcome `is_incomplete()` (objects failed or the mark was unreadable); the text output prints the token of a state it does not know | must |
| FR-020 | Python and Node.js SHALL expose the same policy (`with_mark_propagation` / `withMarkPropagation`, `mark_propagation` / `markPropagation`, `ConfigSetting` `mark_propagation`) and report fields (`mark_propagation` state, `marks_written`, `marks_failed` / `markPropagation`, `marksWritten`, `marksFailed`), with type mapping only; the Python `mark_propagation` state is typed `_MarkState | str` and the Node `markPropagation` state `(string & {})`-widened, so a state added to core later is not a type error in the stubs, and tests tie the stub literals to `MarkState::NAMES` | must |
| FR-021 | `SafePath` SHALL refuse `:` in an entry name on Windows only (alternate data streams); other hosts treat `:` as an ordinary file-name character, so such an entry extracts as a plain file and, under `when_marked`, is marked like any other file | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | All propagation logic lives in `exarch-core` (`src/mark/`); bindings and CLI map types only |
| NFR-002 | Security | No mark data comes from archive content; on Windows `:` in an entry name stays refused by `SafePath`. On other hosts no stream exists to name, so content cannot create a mark by name (the draft claimed refusal on every platform; that was wrong) |
| NFR-003 | Security | Writes are handle-relative only (FR-006); no path-based `setxattr` or `CreateFile` on a stream path string |
| NFR-004 | Security | The source mark is bounded (macOS 256 bytes, Windows first 4096 bytes) and parsed strictly; malformed input cannot panic or allocate without bound and yields the conservative mark |
| NFR-005 | Performance | Under `Never` no syscall is added and the extraction tree is identical (`tests/mark_never_equivalence.rs`); under `WhenMarked` the mark is read once per archive and each object costs one write |
| NFR-006 | Type safety | Policy, outcome and zone/quarantine values are enums or newtypes with private constructors; counters are `usize`; the platform `Mark` is uninhabited where no mark exists |
| NFR-007 | Compatibility | Default `Never` leaves behavior unchanged; `unsafe_code` stays denied (macOS uses `rustix`, Windows goes through `pinned_dir`) |
| NFR-008 | Documentation | `skills/exarch-cli` (`SKILL.md`, `references/extract.md`, `json-output.md`, `security-model.md`) documents the flag, JSON fields and platform behavior |

## 5. Data Model

| Entity | Description |
|--------|-------------|
| `MarkPropagation` | Policy: `Never` (default), `WhenMarked` |
| `MarkOutcome` | Report state: `NotRequested`, `UnsupportedPlatform`, `Unmarked`, `Unreadable`, `Propagated { marked, failed }`; `state()` gives the token enum `MarkState` |
| `MarkState` | Closed token enum of the outcome kinds (`not_requested`, `unsupported_platform`, `unmarked`, `unreadable`, `propagated`) used by the CLI JSON, Python and Node |
| `MarkScope` (crate-private) | Opens a `MarkRun` under `WhenMarked` and, through `around`, always stamps its outcome into the report the extraction returns, a partial one included; the stamp is private, so an entry point cannot lend the mark and forget to report it |
| `MarkRun` (crate-private) | Source mark read once plus the `marked` and `failed` counters; exists only under `WhenMarked`, inside a `MarkScope` |
| `Zone` / `Quarantine` (crate-private) | Parsed source value; render yields the per-object mark |
| `ExtractionReport::mark` | Carries the `MarkOutcome` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Unmarked archive | `Unmarked`, no writes (FR-004) |
| Linux host | `UnsupportedPlatform`, nothing read or written (FR-011) |
| Reader, bytes or sink source | Nothing to propagate (FR-012) |
| Windows source volume without named streams | `Unmarked`; a failing volume query falls through to the stream read, whose error is `Unreadable` (FR-010) |
| Destination filesystem without xattr or streams | Per-object failure counted, extraction exits `0`, text output warns (FR-017) |
| Present but malformed or oversized source mark | Conservative mark propagated (FR-010) |
| I/O error reading the source mark | `Unreadable`, nothing marked, warning (FR-010) |
| Read-only entry (`0444`) | Marked first, then final mode applied (FR-007) |
| Mark write fails | Final mode still applied; `failed` incremented (FR-007, FR-017) |
| `--force` replacement | The replacement file is marked with its exact mode (FR-003) |
| Hardlink entry | Its own copy is marked and counted (FR-003) |
| Symlink entry | Not marked, target not followed (FR-014) |
| Pre-existing directory, destination root (macOS) | Not marked (FR-015) |
| `--atomic` | Marks survive the publish (FR-016) |
| Archive replaced after listing (listed route) | Mark comes from the listed handle (FR-005) |
| Entry named `x:Zone.Identifier` or `x::$DATA` | Windows: extraction refused, nothing written. macOS: plain files with those names, marked like any file (FR-021) |
| PAX `com.apple.quarantine` record | Ignored (FR-013) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Extracted files carrying the mark on a marked archive under `when_marked` (TAR, ZIP, 7z, listed route, `--atomic`, `--force`) | 100% on macOS, covered by `tests/mark_propagation.rs`; Windows pending #1150 |
| SC-002 | Marks under `Never` or from an unmarked archive | 0; trees identical under every policy (`tests/mark_never_equivalence.rs`) |
| SC-003 | Mark writes through path strings | 0 |
| SC-004 | Attacker-supplied xattr, ACL or stream content reaching an extracted file | 0 |
| SC-005 | Python and Node.js parity tests for policy and report fields | pass |

## 8. Agent Boundaries

### Always
- Keep logic in `exarch-core`; run `rust-security-maintenance` after any change to handles or platform code.
- Update `skills/exarch-cli` and CHANGELOG in the same change; verify against the built binary.

### Ask First
- Changing the default from `Never`; adding a strict mode; carrying `ReferrerUrl` / `HostUrl`; adding a dependency or `unsafe`.

### Never
- Copy any xattr, ACL or stream from archive content; open `file:Zone.Identifier` by path; mark symlinks or follow them; weaken the Windows `:` refusal.

## 9. Open Items

> [!question] Open
> - The Windows implementation (`src/mark/windows.rs`, `zone.rs`, the `pinned_dir` stream helpers) runs only on the CI Windows runner (NTFS: stream volume check, `ZoneId=3` fallback for a malformed or oversized source stream, read-only entry keeps its mark); the branch for a volume without named streams, and ReFS, SMB and FAT/exFAT hosts, are not executed anywhere and stay tracked in #1150.
> - Office-only selection (7-Zip mode 2) and a strict mode are not planned.

## 10. See Also

- [[constitution]], [[MOC-specs]]
- [[022-extract-entry-selection/spec|Extract Entry Selection]] - sibling extraction option
- [[005-cli/spec|CLI]] - flag and JSON surface
- `https://isc.sans.edu/diary/28810` - 7-Zip Zone.Identifier propagation (2022)
- zip2 GHSA-7r34 - a colon in an entry name wrote an alternate data stream on Windows
