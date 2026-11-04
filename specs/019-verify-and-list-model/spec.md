---
aliases:
  - Verify and List Reporting Model
  - ArchiveManifest and VerificationReport
tags:
  - sdd
  - spec
  - security
  - rust
  - inspection
created: 2026-10-26
updated: 2026-11-04
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-exarch-system/spec]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[005-cli/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[018-7z-stream-map-panic/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Verify and List Reporting Model

> [!note] Revision 2026-11-04 (50-issue batch)
> `ArchiveEntry` carries `size()` and a typed `mode` (#910); `VerificationIssue` holds a typed `Finding` with private fields (#899); `ArchiveEntry::utf8_path` (#925); `ArchiveManifest::landing_paths` (#933); verify shares the landing projection with extract (#945); entry points are request types (#912). See FR-057 to FR-064; rows that conflict are rewritten in place.

> [!info] Metadata
> **Subsystem**: exarch-core / `inspection` (`manifest`, `report`, `verify`, `list`, `integrity`),
> `config` (`VerificationOptions`, `ListOptions`), `security::fs_view`
> **MSRV**: Rust 1.98.0
> **Origin**: v0.7.0 inspection work (typed manifest, derived report status, opt-in integrity check)
> **Status**: implemented — this spec documents shipped behavior, extracted as its own unit because
> the archived monolithic [[001-exarch-system/spec]] only describes the pre-0.7.0 flat shapes

## 1. Overview

### Problem Statement

`list_archive` and `verify_archive` inspect an untrusted archive without writing to the
destination. Their result types must not be able to contradict themselves (a report whose status
disagrees with its issues, a manifest whose total disagrees with its entries), must not let a link
entry carry a target it cannot have, and must say honestly what was and was not checked. Earlier
shapes were flat structs with public status fields, an `entry_type` plus optional target pair, and
no way to request payload verification or to express "the target exists but was not read".

### Goal

Specify the typed reporting model: a manifest whose entry kind carries link targets and
compression state in the type, a report whose statuses are derived from its issue list, an explicit
opt-in integrity check, and an in-memory model of the extraction tree so verification never writes
to disk.

### Out of Scope

- The ZIP structure findings themselves (`ZipInconsistency`) — see [[017-zip-header-consistency/spec]]
- 7z stream-map handling and panic hardening — see [[018-7z-stream-map-panic/spec]]
- Extraction-time validation against the real destination (`HostFs`) — see
  [[001-security-pipeline/spec]]
- Binding and CLI output shapes beyond the facts named here — see [[005-cli/spec]],
  [[006-python-bindings/spec]], [[007-node-bindings/spec]]

## 2. User Stories

### US-001: Honest Listing

AS A caller listing an untrusted archive
I WANT each entry's kind to carry its link target, and to know when a target was not read
SO THAT a regular file cannot carry a target and an absent target is never mistaken for an empty one

**Acceptance criteria:**
```
GIVEN a 7z archive with a symlink and the default ListOptions
WHEN list_archive_with_options() runs
THEN the entry kind is Symlink { target: LinkTarget::Unread } and no entry data was decoded

GIVEN the same archive with StoredTargets::Read
WHEN list_archive_with_options() runs
THEN the target is LinkTarget::Recorded(path)
```

### US-002: Report That Cannot Contradict Itself

AS A caller of verify_archive()
I WANT status, security status and integrity status derived from the issue list
SO THAT no report can claim PASS while holding a Medium-or-higher issue

**Acceptance criteria:**
```
GIVEN a report with any High or Critical issue
THEN status() is Fail

GIVEN a report whose highest issue is Medium
THEN status() is Warning and is_safe() is false

GIVEN a report built without an integrity request
THEN integrity_status() is Skipped
```

### US-003: Opt-In Payload Integrity

AS A caller vetting an archive before use
I WANT to request a decode-to-EOF integrity check with a bounded extra decoding budget
SO THAT corruption is detected, and anything the check could not cover is reported as INCOMPLETE
rather than silently passed

**Acceptance criteria:**
```
GIVEN VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(budget))
WHEN verify_archive_with_options() runs on a corrupt payload
THEN integrity_status() is Fail and a High CorruptData issue is present

GIVEN a budget that cannot cover part of the payload
THEN integrity_status() is Incomplete, one Medium IntegrityIncomplete issue is present, and
     integrity_gaps() lists what was not verified
```

### US-004: Verification Without Touching the Disk

AS A caller verifying an untrusted archive
I WANT entries validated against an in-memory model of the extracted tree
SO THAT link escapes, entries under files and overwrite conflicts are found without any write

## 3. Functional Requirements

### 3.1 Manifest

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `ArchiveManifest` SHALL keep its fields private; `entries()`, `into_entries()`, `total_entries()`, `total_size()`, `format()` and `oversized_entries()` are the accessors, and `add_entry` SHALL fail with `ArchiveError::InvalidArchive` when the total size would overflow `u64` | must |
| FR-002 | `ArchiveEntry` SHALL be `#[non_exhaustive]` with public fields `path`, `kind: ManifestEntryKind`, `size`, `compression: EntryCompression`, `mode: Option<u32>`, `modified: Option<SystemTime>`, and be constructed with `ArchiveEntry::new(path, kind, size)` (compression `Unknown`, mode and modified unset) | must |
| FR-003 | `ManifestEntryKind` SHALL be `#[non_exhaustive]` with variants `File`, `Directory`, `Symlink { target: LinkTarget }`, `Hardlink { target: LinkTarget }`, so only link kinds can carry a target; helpers `entry_type()` (to `ManifestEntryType`), `is_link()`, `symlink_target()`, `hardlink_target()`, `link_target()` | must |
| FR-004 | `LinkTarget` SHALL be `#[non_exhaustive]` with variants `Recorded(PathBuf)` (within the host's name limits), `Missing` (archive stores no target), `Unread` (stored in compressed entry data and not read), `Unreadable` (a 7z reparse point, or a target whose read was attempted and failed), `Oversized { bytes }` (only the length is kept); `path()` SHALL return `Some` only for `Recorded`; `classify(path, LinkKind)` SHALL return `Recorded` or `Oversized` by the host name limits | must |
| FR-005 | `Missing` and `Oversized` targets and `OversizedEntry` records SHALL occur only in the manifest produced by `verify`'s pre-flight listing, where they become report issues; a bare listing SHALL fail instead | must |
| FR-006 | `EntryCompression` SHALL be `#[non_exhaustive]` with `Unknown` (TAR, or an entry with no data stream), `Entry(u64)` (ZIP, 7z single-file block), `SolidBlockStart(SolidBlock)` (carries block `compressed` and `uncompressed` totals) and `SolidBlockMember`; `compressed_size()` SHALL report the block size for a solid block start, and `ArchiveEntry::compression_ratio()` SHALL be `Some` only for `Entry` with a non-zero compressed size, so no per-file ratio exists for solid members | must |
| FR-007 | `OversizedEntry { index, bytes }` SHALL record an entry dropped from the manifest because its path exceeds the host's name limits, keeping only its listing position (kept and dropped entries both count) and path length | must |

### 3.2 Report

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | `VerificationReport` SHALL keep its fields private and expose `status()`, `security_status()`, `integrity_status()`, `integrity_gaps()`, `issues()`, `into_issues()`, `total_entries()`, `suspicious_entries()`, `total_size()`, `format()`, `is_safe()`, `has_critical_issues()` and `issues_by_severity()` | must |
| FR-011 | Issues SHALL be sorted from most to least severe (`IssueSeverity`: Info, Low, Medium, High, Critical) | must |
| FR-012 | `status()` SHALL be `Fail` when any issue is High or Critical, else `Warning` when any is Medium, else `Pass`; `is_safe()` SHALL equal `status() == Pass` | must |
| FR-013 | `suspicious_entries()` SHALL count entries with at least one Medium-or-higher issue, counting an entry once however many issues it has; archive-level issues are not entries and are not counted but still decide `status()` | must |
| FR-014 | `security_status()` (`CheckStatus`: Pass, Fail, Warning, Skipped) SHALL be derived only from issues whose category `is_security()`: `Fail` for any Critical or High, else `Warning`, else `Pass`; a Low `NameCollision` (two directories merging with no contents) SHALL be reported but not counted | must |
| FR-015 | `IssueCategory` SHALL be `#[non_exhaustive]`; `is_security()` SHALL match exhaustively so a new category must be classified. Security categories: `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `ZipBomb`, `InvalidPermissions`, `QuotaExceeded`, `SecurityPolicy`, `HeaderMismatch`, `DuplicateEntry`, `OverlappingEntries`, `HiddenEntry`, `NameCollision`. Non-security categories: `InvalidArchive`, `SuspiciousPath`, `ExecutableFile`, `CorruptData`, `IntegrityIncomplete`, `ArchiveNote` | must |
| FR-016 | `VerificationIssue::from_error` SHALL map `SecurityViolation` to `SecurityPolicy` (High) and ZIP structure findings to `HeaderMismatch`, `DuplicateEntry`, `OverlappingEntries` or `HiddenEntry` (High); `ArchiveNote` is an informational category for notes that need no action, such as skipped 7z anti-items | must |
| FR-017 | Heuristic issues SHALL be: `ExecutableFile` (Low, regular file with an execute bit), `SuspiciousPath` (Info for extensions `exe`, `dll`, `sh`, `bat`, `cmd`; Medium for a non-UTF-8 name), and `InvalidPermissions` (Medium, mode changed by `sanitize_permissions`; a link entry's recorded mode is not checked because extraction never applies it) | must |

### 3.3 Integrity

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | `verify_archive(path, config)` SHALL equal `VerifyRequest::new(config).verify(path)` with `VerificationOptions::default()`, whose `integrity` is `IntegrityCheck::Skip` (`verify_archive_with_options` was removed, #912) | must |
| FR-021 | `IntegrityCheck` SHALL be `#[non_exhaustive]` with `Skip` (default) and `DecodeToEof(DecompressionBudget)`, so a budget without a check is unrepresentable; `VerificationOptions` SHALL be `#[non_exhaustive]` with `with_integrity()`; `IntegrityCheck::budget(self) -> Option<DecompressionBudget>` SHALL match exhaustively so bindings need no wildcard arm (#922) | must |
| FR-022 | `DecompressionBudget` SHALL wrap a `NonZeroU64` (`try_from_bytes(0)` is `InvalidConfiguration`) with `DEFAULT` of 500 MiB, independent of `max_total_size`; it bounds decoding beyond what listing already does (ZIP entries and 7z blocks charged their declared size, TAR entry content and the compressed TAR tail after the end marker not charged; that tail is bounded by `max_tar_metadata_bytes`, at least 1 MiB, and a longer one fails the call) | must |
| FR-023 | `IntegrityStatus` SHALL be `#[non_exhaustive]` with `Pass` ("OK"), `Fail` ("FAILED"), `Incomplete` ("INCOMPLETE"), `Skipped` ("SKIPPED"); derivation: any `CorruptData` issue gives `Fail`; otherwise no integrity request gives `Skipped`; otherwise any `IntegrityIncomplete` issue gives `Incomplete`; otherwise `Pass` | must |
| FR-024 | `Pass` SHALL mean every payload byte was decoded and every checksum the format has matched; for formats without payload checksums (plain TAR, 7z entries without CRC, zstd frames without a content checksum) it means the data was complete and decodable | must |
| FR-025 | A checksum or decoder failure SHALL be a High `CorruptData` issue; everything not verified SHALL be counted per `UnverifiedReason` and reported as one archive-level Medium `IntegrityIncomplete` issue, so overall status is at least `Warning` | must |
| FR-026 | `UnverifiedReason` SHALL be `#[non_exhaustive]` with `OverBudget`, `ResourceLimit`, `SolidPolicy`, `SizeCeiling`, `UncoveredBlockCrc`, `NotDecodable`, `NoEndMarker`, `PathTooLong`, `DescriptorTail`, each with a stable snake_case string form shared by the CLI JSON and bindings and a `description()` | must |
| FR-027 | `IntegrityGaps` SHALL derive from one value the counts, the listed entries and the issue message: `counts()` (reason order, absent when zero), `count(reason)`, `total()`, `is_empty()`, `entries()` (`UnverifiedEntry { path, reason }`, capped at 256) and `omitted()`; `integrity_gaps()` SHALL be `None` when no check was requested and an empty value when everything was verified | must |
| FR-028 | With integrity requested, a TAR entry whose content fails to decode or is cut short SHALL fail the call with `ArchiveError::InvalidArchive` rather than yield a partial report; corruption in a TAR trailer (a gzip CRC, an xz index) SHALL be a `Fail` report | must |
| FR-029 | The CLI SHALL map the option to `verify --check-integrity` with `--decompression-budget SIZE` (requires `--check-integrity`) and `--strict` (exit status 3 on warnings, #932); exit code 0 SHALL NOT be read as integrity `OK` | must |

### 3.4 Listing options

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `list_archive(path, config)` SHALL equal `ListRequest::new(config).list(path)` with `ListOptions::default()` (`list_archive_with_options` was removed, #912) | must |
| FR-031 | `ListOptions` SHALL be `#[non_exhaustive]` with `stored_targets: StoredTargets` and `with_stored_targets()`; `StoredTargets` SHALL be `#[non_exhaustive]` with `Skip` (default; 7z link targets stay `Unread`, no entry data decoded) and `Read` (decodes the blocks that hold the targets) | must |
| FR-032 | Only 7z keeps link targets in compressed entry data; TAR and ZIP always report their targets. `StoredTargets` SHALL be a Rust API and CLI (`list --read-link-targets`) option; Python and Node `list_archive` skip 7z targets | must |
| FR-033 | A 7z reparse point SHALL be `LinkTarget::Unreadable` in every listing | must |
| FR-034 | The listing mode SHALL be an internal two-variant `ListPass`: `Strict(StoredTargets)` (every policy violation fails the listing) and `VerifyPreflight(Option<&mut IntegrityPass>)` (defers rejections to report issues, lifts only the per-file size limit, and is the only mode that can decode payloads) | must |

### 3.5 In-memory tree model

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | Verification SHALL validate entries against a `VirtualTree` of what extraction would create, rooted at a fixed virtual root path (`/exarch-virtual-root`, `C:\exarch-virtual-root` on Windows) used only as a path anchor; `verify` SHALL create no temporary directory and no archive content SHALL be written (v0.8.0, #754, #771) | must |
| FR-041 | Each entry SHALL pass, in order: name-length check, `SafePath::validate_in`, quota reserve, compression-ratio check, then link validation (`SafeSymlink::validate_in` / `HardlinkTracker::validate_hardlink_in`) against the tree; link escapes SHALL be reported as `SymlinkEscape` / `HardlinkEscape` | must |
| FR-042 | Tree nodes SHALL be `Dir`, `File`, `Symlink(target)` and `OpaqueSymlink` (a link whose target was not read: it exists but a path resolving through or onto it is an error) | must |
| FR-043 | The first entry at a path SHALL win, mirroring extraction that skips an existing entry; a symlink over an earlier file SHALL replace it in the tree and be reported as a security finding (`SecurityPolicy`), since overwrite semantics would change what the path resolves to | must |
| FR-044 | A conflict where overwriting fails closed and replaces nothing (symlink over a directory or a symlink with another target, file over a directory or symlink, hardlink over any earlier entry) SHALL be a Low `InvalidArchive` note naming the earlier occupant, leaving status `Pass`; a symlink repeating an earlier symlink's target SHALL not be noted | must |
| FR-045 | An entry whose parent is a file or a dangling symlink, a parent chain that loops or leaves the root, or a directory entry over a non-directory SHALL be reported: as a `SecurityPolicy` violation when a link is involved (the entry is one, or the path crosses one), otherwise as an `InvalidArchive` I/O finding | must |
| FR-046 | Hardlinks SHALL be materialized after every other entry: link path and target are re-validated against the final tree, the target must exist and must not resolve to a directory, and a hardlink cannot replace an existing entry | must |
| FR-047 | Symlink chains SHALL be cut off after `MAX_SYMLINK_HOPS` (macOS 33, glibc 40, musl 39, Windows 63 unverified, other Unix 32), matching `std::fs::canonicalize` | must |
| FR-048 | Name lengths SHALL use per-OS limits (`MAX_COMPONENT_LEN` 255, `MAX_PATH_LEN` Linux 4095, macOS and other Unix 1023, Windows 32767 UTF-16 units); a symlink target is checked against `MAX_SYMLINK_TARGET_LEN` only. Over-long entries SHALL be dropped to `OversizedEntry` and reported as I/O issues, the first 16 individually and the rest in one closing issue | must |
| FR-049 | Names SHALL be compared after NFD plus a per-character case fold on macOS, the same fold without normalisation on Windows, and exactly elsewhere (under `PathModel::Portable` the macOS fold applies on every host and the name limits are fixed at 255 per component and 1023 per path); two names that differ exactly but fold equal SHALL be recorded as a `NameCollision` and never merged silently. Severity: `CollisionKind::Mixed` (kinds differ or a symlink involved) High; `Files` and `DirectoriesWithContents` Medium; `Directories` (neither holds entries) Low | must |
| FR-050 | Symlinks whose targets are `Unread` while symlinks are allowed SHALL produce one archive-level Medium `SecurityPolicy` issue counting them; entries beneath or through an unread link are reported as failures. With symlinks disallowed, an `Unread` or `Unreadable` target SHALL be reported as the policy violation | must |
| FR-051 | A missing link target SHALL be reported as a `SecurityPolicy` violation | must |

### 3.6 Entry points and in-memory budget (v0.8.0)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-052 | `ListRequest::{list, list_reader}` and `VerifyRequest::{verify, verify_reader}` (with or without `with_progress`) SHALL produce the manifest and report defined above for TAR, ZIP and 7z; the reader forms take an `ArchiveReader` instead of a path ([[020-reader-sink-and-in-memory-api/spec]]) and the progress forms follow [[004-progress-tracking/spec]] (#754, #771, #782, #790; the free functions `list_reader*`, `verify_reader*` and `*_with_progress` were removed, #912) | must |
| FR-053 | The in-memory tree SHALL charge every distinct name against a node budget of `max_file_count * max_path_depth + 1` and fail with `QuotaExceeded { resource: TreeNodes { max } }` when it is exhausted; a link path that leaves the root and returns SHALL be an escape, though the host would resolve it inside (#778, #779, #787) | must |
| FR-054 | A directory entry over a file or a symlink SHALL be refused with the same entry-naming message in `extract` and `verify` (#802, #803) | must |
| FR-055 | WHEN `list_archive` applies the extension allowlist, a skipped entry SHALL be charged to `max_file_count` only and not to `max_total_size`, and its path SHALL be validated as in `extract`; WHEN `verify` runs with the integrity check on a compressed TAR, the decode of allowlist-skipped entries SHALL be bounded as in `extract` and `list` (`ZipBombScope::SkippedEntries`); a TAR header ambiguity SHALL be refused with `TarAmbiguity` by `list`, `verify` and `extract` alike (see [[002-format-handlers/spec]] FR-051, FR-053, FR-054) (v0.8.0, #820, #846, #868, #894) | must |
| FR-056 | `ListRequest::for_extraction(path, DecodeReuse)` SHALL return a `ListedArchive` that keeps the list pass's decode for extraction and the extraction config it will run under (see [[020-reader-sink-and-in-memory-api/spec]] FR-100 to FR-103) (v0.8.0, #828, #884; `list_archive_for_extraction` removed, #901, #912) | should |
| FR-057 | `ManifestEntryKind::File` SHALL carry `size: Uncompressed`; `ArchiveEntry` SHALL NOT have a `size` field and SHALL expose `size()` (0 unless the entry is a regular file) and `mode: Option<RawMode>`; `ArchiveManifest::total_size()` SHALL sum regular files only (a ZIP symlink's data size no longer counts; list-time quota still charges raw sizes and symlink data is capped by the symlink-target limit); `InvalidPermissions` SHALL carry `mode: RawMode` (#910) | must |
| FR-058 | `VerificationIssue` SHALL have private fields and hold a typed `Finding`: `Refusal { category, kind: FfiKind, message }` for a refusal (so its `FfiKind`, sub-code and `relaxable_by` survive to the front ends) or `Heuristic(Heuristic)`; `category()`, `message()`, `ffi_kind()` and `mode() -> Option<RawMode>` (the raw mode of an executable-file or invalid-permissions finding) are derived; message texts are unchanged except that entry paths in them are rendered with `path_text` and host paths keep their native spelling; `context` is removed (#899, #925) | must |
| FR-059 | `ArchiveEntry::utf8_path()` SHALL return the path as `&str` or `Malformation::EntryPathNotUtf8`, so a front end that needs text decides to refuse rather than to lose bytes (Python converts lossless with `os.fsdecode`, Node refuses in listings and escapes elsewhere; see [[006-python-bindings/spec]] FR-101 and [[007-node-bindings/spec]] FR-112) (#925) | must |
| FR-060 | `ArchiveManifest::landing_paths(&self, &SecurityConfig) -> impl Iterator<Item = (&ArchiveEntry, LandingPath)>` SHALL give where each entry lands: destination-relative, normalized (`./`, `/`, `\` and drive prefixes handled as extraction does), projected through in-archive links with `VirtualTree::project_landing`; it SHALL cover all entry kinds and omit validation refusals, symlinks and hardlinks the config disallows, symlinks whose target is `Missing`, `Unread`, `Unreadable` or `Oversized`, placement conflicts, over-long landings and regular files skipped by the extension allowlist; a hardlink lands as a file without checking its target exists (verify defers that); `ArchiveManifest::landings(&SecurityConfig)` SHALL yield the same paths as `Landing { path(), kind() }` with `LandingKind::{Entry(&ArchiveEntry), ImplicitParent}` and additionally every parent directory extraction creates implicitly (each reported once, before the first path below it), which is what the CLI conflict pre-check reads; differential tests prove the set of non-directory landings equals the set actually extracted for TAR (`./`, `/abs`, directory, symlinked parent), ZIP (`\`, `C:\`, `/abs`) and 7z (#933) | must |
| FR-061 | `verify`, `extract` and the sinks SHALL agree on the projected landing length through one projection (`VirtualTree::project_landing` with `LandingLimits::{Enforced, Exempt}` and `projected_landing_within_limits`): verify no longer judges only an entry's own name length (it reported PASS for a landing through a symlink that `extract` refused with "file name too long"); an extension-skipped regular file stays exempt; a parity test (`d -> cc` plus a long tail) pins the verdict (#945, #903) | must |
| FR-062 | `VerificationIssue` SHALL keep the typed refusal in every front end: CLI `--json` adds `code`, `sub_code`, `relaxable_by` and `setting`, Python `VerificationIssue` the same plus `mode`, Node `code`, `subCode`, `relaxableBy`, `setting` and `ioKind` (see [[005-cli/spec]] FR-120) (#899) | must |
| FR-063 | `ManifestEntryType`, `CheckStatus`, `IssueSeverity` and `VerificationStatus` SHALL be closed enums (`closed_enum`) with `ALL`, documented as closed by design; two entries whose names differ only in invalid bytes SHALL not be folded into one `NameCollision` under the host path model (#905, #925) | must |
| FR-064 | `inspection::{list,verify}::*_with_progress` SHALL be crate-private, taking options by value, with the public surface being the request types (#912) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | Verification SHALL perform no write of archive content; no `unsafe` code is used |
| NFR-002 | Resource bounds | Over-long names and targets keep only their length, issue lists for oversized entries are capped, and `IntegrityGaps` lists at most 256 entries, so a hostile archive cannot inflate the manifest or report |
| NFR-003 | API stability | `ArchiveEntry`, `ManifestEntryKind`, `LinkTarget`, `EntryCompression`, `SolidBlock`, `OversizedEntry`, `IssueCategory`, `IntegrityStatus`, `UnverifiedReason`, `IntegrityCheck`, `VerificationOptions`, `ListOptions`, `StoredTargets`, `Heuristic` and `VerificationIssue` are `#[non_exhaustive]`; downstream matches need a wildcard arm; `ManifestEntryType`, `CheckStatus`, `IssueSeverity` and `VerificationStatus` are closed enums with `ALL` and a drift test in each consumer (#905) |
| NFR-004 | Honesty | Every limit of the model (destination state, host fold approximation, overwrite semantics, destination prefix length) is documented on `verify_archive`; a `Pass` does not guarantee extraction into a non-empty destination succeeds |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ArchiveManifest` | Listing result | private entries, oversized records, total size, `ArchiveType` |
| `ArchiveEntry` | One listed entry | `path`, `kind`, `compression`, `mode: Option<RawMode>`, `modified`; `size()` (0 unless a regular file); `utf8_path() -> Result<&str, Malformation>` |
| `ManifestEntryKind` | Entry kind with its link target | `File { size: Uncompressed }`, `Directory`, `Symlink { target }`, `Hardlink { target }` |
| `LandingPath` | Destination-relative path an entry lands at, a lexical-stage newtype (not a `SafePath`; no containment claim) | `as_path()`, `into_path_buf()`, `AsRef<Path>` |
| `ManifestEntryType` | Closed wire tag of a kind | `File`, `Directory`, `Symlink`, `Hardlink` |
| `LinkTarget` | Target as far as listing kept it | `Recorded`, `Missing`, `Unread`, `Unreadable`, `Oversized { bytes }` |
| `EntryCompression` / `SolidBlock` | Compressed-size attribution | `Unknown`, `Entry`, `SolidBlockStart`, `SolidBlockMember`; block `compressed`, `uncompressed` |
| `OversizedEntry` | Entry dropped for path length | `index`, `bytes` |
| `VerificationReport` | Derived-status report | issues, integrity scope, totals, format |
| `VerificationIssue` | One finding; private fields (#899) | `severity()`, `entry_path()`, `finding()`, derived `category()`, `message()`, `ffi_kind() -> Option<&FfiKind>`; `context` was removed |
| `Finding` / `Heuristic` | What a finding is: `Refusal { category, kind: FfiKind, message }` or `Heuristic(Heuristic)` (#899) | `Heuristic` is `#[non_exhaustive]`: `ExecutableFile { mode: RawMode }`, `SuspiciousExtension`, `NonUtf8Name`, `NameCollision`, `OverwriteConflict`, `UnreadSymlinkTargets`, `IntegrityIncomplete`, `CorruptData`, `AntiItemsSkipped`, `OmittedRefusals`, `OmittedStructureFindings` |
| `VerificationStatus` | Overall; closed enum with `ALL` (a drift test per consumer, #905) | `Pass` ("PASS"), `Fail` ("FAIL"), `Warning` ("WARNING") |
| `CheckStatus` | Security check | `Pass` ("OK"), `Fail` ("FAILED"), `Warning`, `Skipped` |
| `IntegrityStatus` | Payload check | `Pass` ("OK"), `Fail` ("FAILED"), `Incomplete`, `Skipped` |
| `IntegrityGaps` / `UnverifiedEntry` / `UnverifiedReason` | What the check left unverified | counts per reason, listed entries, `omitted` |
| `VerificationOptions` / `IntegrityCheck` / `DecompressionBudget` | Integrity request | `Skip` or `DecodeToEof(budget)`; default budget 500 MiB |
| `ListOptions` / `StoredTargets` | Listing request | `Skip` (default) or `Read` |
| `VirtualTree` / `Node` / `Occupant` / `CollisionKind` | In-memory extraction model | see FR-040 to FR-049 |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Entry name with `..` or an absolute path (without `allowed.absolute_paths`) | Listing fails with `PathTraversal` before a report exists |
| ZIP central directory with more records than `max_file_count` | Call fails; `total_entries()` is the raw central directory count |
| 7z symlink, default listing | `LinkTarget::Unread`; `verify` without integrity reports one Medium `SecurityPolicy` issue |
| 7z symlink, integrity budget too small | Target stays `Unread`, gap reason `OverBudget` or `ResourceLimit` |
| Entry under a regular file | Conflict at the parent; `InvalidArchive` I/O finding, or `SecurityPolicy` if a link is on the path |
| Symlink pointing outside the destination | `SymlinkEscape` Critical |
| Hardlink whose target never appears | Reported after materialization, target missing |
| `Cafe.txt` and `cafe.txt` on macOS or Windows host | `NameCollision` Medium (two files) |
| Two empty directories folding equal | Low `NameCollision`, not counted by `security_status()`; if either later gains an entry it is reported at its real severity |
| TAR stream without an end-of-archive marker, integrity requested | Gap reason `NoEndMarker`, integrity `Incomplete` |
| Compressed TAR with more than the trailer cap after the end marker, integrity requested | `ArchiveError::TarTrailer(OverCap)` (reported as `SecurityViolation`, relaxable by `max_tar_metadata_bytes`), not a gap; plain `verify` does not read the tail |
| Solid 7z with solid archives refused (`SolidArchives::Refuse`), integrity requested | Gap reason `SolidPolicy`, integrity `Incomplete` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | A report whose status contradicts its issues | Impossible — statuses are derived, fields private |
| SC-002 | A regular file carrying a link target, or a budget without an integrity check | Impossible — unrepresentable in the types |
| SC-003 | Verification writing archive content to disk | Never — tree model only |
| SC-004 | A skipped or partial integrity check reported as OK | Never — `Skipped` / `Incomplete` with a Medium issue |

## 8. Agent Boundaries

### Always (without asking)
- Derive any new status from the issue list rather than storing it
- Classify a new `IssueCategory` in `is_security()` (the match is exhaustive on purpose)
- Add a wildcard arm when matching the `#[non_exhaustive]` types above from another crate
- Update `skills/exarch-cli/SKILL.md` when `verify` / `list` flags, JSON or exit codes change

### Ask First
- Changing a severity mapping (it moves `status()` and the CLI exit code)
- Raising the 256-entry or 16-issue caps

### Never
- Write archive content to disk during `verify`
- Report an unread or unreadable link target as validated
- Add a public constructor or setter that lets a report or manifest be built inconsistent with its contents

## 9. Open Questions

None — retrospective spec documenting shipped behavior.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-exarch-system/spec]] — archived monolithic spec (FR-050 to FR-052)
- [[001-security-pipeline/spec]] — the validation pipeline verification reuses
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — `IssueCategory` non-exhaustive hardening
- [[017-zip-header-consistency/spec]] — ZIP structure findings reported as issues
- [[018-7z-stream-map-panic/spec]] — 7z stream-map handling
- [[020-reader-sink-and-in-memory-api/spec]] — reader entry points, sink extraction over the same in-memory tree
- `crates/exarch-core/src/inspection/manifest.rs`, `report.rs`, `verify.rs`, `list.rs`, `integrity.rs`
- `crates/exarch-core/src/config.rs` — `VerificationOptions`, `IntegrityCheck`, `DecompressionBudget`, `ListOptions`, `StoredTargets`
- `crates/exarch-core/src/security/fs_view.rs` — `VirtualTree`, limits, `NameCollision`
