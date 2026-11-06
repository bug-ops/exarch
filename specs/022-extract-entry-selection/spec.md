---
aliases:
  - Extract Entry Selection
  - Strip Components and Entry Filters
  - EntrySelection and StripComponents
tags:
  - sdd
  - spec
  - extraction
  - security
  - parity
  - rust
created: 2026-11-06
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
  - "[[021-create-staging-and-output-policy/spec]]"
---

# Feature: Extract Entry Selection and Path Stripping

> [!info] Metadata
> **Subsystem**: exarch-core / `config` (extraction options), `request` (`ExtractRequest`, `ListRequest`, `VerifyRequest`, `SinkExtractRequest`), `security` (`SafePath`, `ValidatorCore`), `inspection::landing`, `formats::{tar,zip,sevenz}`; surfaces in `exarch-cli`, `exarch-python`, `exarch-node`
> **MSRV**: Rust 1.99.1
> **Origin**: #967 (competitive parity research, P2). No prior request or `wontfix` found in open or closed issues.
> **Status**: draft, research spec. It captures WHAT and WHY; HOW belongs to a later `/sdd plan`.

> [!note] Working names
> `EntrySelection`, `PathRewrite`, `StripComponents`, `SkipKind::NotSelected` and `SkipKind::StrippedAway` are working names used to keep requirements readable. The plan decides the final identifiers.

## 1. Overview

### Problem Statement

`extract` takes a whole archive or filters regular files by extension (`--allowed-extensions`, `SecurityConfig::allowed_extensions`). A caller cannot ask for one file or one subtree, cannot leave a subtree out, and cannot drop leading path components. The missing capability that hurts most is the last one: release tarballs usually wrap everything in one top-level directory (`project-1.2.3/...`), and every other archive tool has the idiom `tar --strip-components=1` to unwrap it. With exarch the caller must extract into a scratch directory, move the files, and delete the scratch directory. That sequence is slower, needs twice the disk, and is exactly the kind of glue code where path-handling mistakes happen.

Creation already has `-x/--exclude` and `--strip-prefix` (spec [[021-create-staging-and-output-policy/spec]]), so the asymmetry is visible in the product. The reference libraries all offer it: `python/cpython` `tarfile` (`members=`, `filter=`), `npm/node-tar` (`strip`, `filter`, a file list), `tenuo-ai/safe_unzip` (`only()`, `include_glob`/`exclude_glob`, `junk_paths`, a filter callback) and `bsdtar`/GNU `tar` (`--strip-components`, member arguments, `--include`/`--exclude`).

For a security-first library the feature is not a convenience layer on top of extraction. Stripping and flattening rewrite the name that the validation pipeline just approved, so a naive implementation reopens path traversal (`top/../x`, a name that becomes empty or `.`), makes link targets point somewhere else than the archive author intended, lets two entries collide on one landing, lets quotas diverge from what was actually written, and lets `verify && extract` gates lie about what `extract` will do.

### Goal

A caller states, in one validated value, which entries to extract and how many leading components to drop (or that paths are flattened); `extract`, `list` and `verify` interpret that value identically, every rewritten name is validated again as a first-class `SafePath`, and every entry that is not extracted is accounted for with the same rules as the existing extension allowlist.

### Out of Scope

- A glob engine. Patterns use exactly the grammar that `create -x/--exclude` accepts today (`Exact`, `Prefix`, `Suffix`, `Path`; see [[021-create-staging-and-output-policy/spec]] FR-019 to FR-021). `**`, `?`, character classes, braces and negation stay refused.
- Regular expressions, and tar-style `s/old/new/` name transforms.
- An overwrite-policy enum (`Skip`/`Overwrite`/`Error`). Collisions follow the existing `skip_duplicates` and `--force` rules; a policy enum is a separate spec.
- A caller-supplied filter callback in `exarch-core` or the bindings (see Open Questions: user code per entry cannot be modeled by `verify`).
- Rewriting link targets so that a link keeps pointing at the same archive entry after stripping.
- Changing creation (`--strip-prefix`, `-x`) in any way.
- Extracting entries by position or by archive index.
- Early termination of the archive scan once all named entries have been found (see NFR-005).

## 2. User Stories

### US-001: Unwrap a release tarball

AS A developer installing a release archive
I WANT `exarch extract project-1.2.3.tar.gz ./src --strip-components 1`
SO THAT the files land in `./src` directly, without a `project-1.2.3/` wrapper and without a scratch directory

**Acceptance criteria:**
```
GIVEN a TAR holding project-1.2.3/, project-1.2.3/README and project-1.2.3/src/main.rs
WHEN extract runs with strip 1 into an empty directory
THEN README and src/main.rs exist at the destination root, no project-1.2.3 directory exists, and the wrapper directory entry is reported as stripped away, not as an error
```

```
GIVEN the same archive and strip 1
WHEN verify runs with the same strip
THEN it reports the same landings that extract writes and the same refusals
```

### US-002: Extract only what I named

AS A script author
I WANT to extract one file or one subtree by archive path
SO THAT I do not write a 2 GiB archive to disk to read one configuration file

**Acceptance criteria:**
```
GIVEN an archive with a/b/c.txt and a/d.txt, and the include pattern a/b
WHEN extract runs
THEN a/b/c.txt is extracted (the pattern selects the subtree), a/d.txt is not, and files_skipped counts a/d.txt as not selected
```

```
GIVEN an include pattern that matches no entry
WHEN extract finishes scanning the archive
THEN it fails with a typed error that names the unmatched pattern, instead of reporting success with nothing extracted
```

### US-003: Leave a subtree out

AS A packager
I WANT an exclude pattern at extraction, with the grammar I already use for `create -x`
SO THAT I learn one pattern language and apply it in both directions

**Acceptance criteria:**
```
GIVEN an archive with src/ and docs/ and the exclude pattern docs
WHEN extract runs
THEN everything except docs and its subtree is extracted
```

```
GIVEN the include pattern src and the exclude pattern src/generated
WHEN extract runs
THEN src is extracted except src/generated (an exclude always wins over an include)
```

### US-004: A stripped name cannot escape

AS A user extracting an untrusted archive
I WANT a stripped, flattened or selected extraction to be exactly as safe as a plain one
SO THAT the convenience flag is never the way around the validator

**Acceptance criteria:**
```
GIVEN an entry named top/../../etc/x and strip 1
WHEN extract runs
THEN it is refused with the same PathTraversal error a plain extraction gives, before any write
```

```
GIVEN an entry named top/ and strip 1 (nothing remains after stripping)
WHEN extract runs
THEN the entry is skipped and counted, no write happens for it, and the destination root itself is not touched
```

### US-005: Predictable gates

AS A CI maintainer
I WANT `verify` and `list` to take the same selection and strip as `extract`
SO THAT `exarch verify a.tgz --strip-components 1 && exarch extract a.tgz out --strip-components 1` still means what it says

**Acceptance criteria:**
```
GIVEN any archive and any selection
WHEN verify and extract run with that selection
THEN every landing extract writes is a landing verify reported, and every refusal extract raises is a verify issue
```

### US-006: Same behavior in Python and Node.js

AS A binding user
I WANT `strip_components`, include patterns and exclude patterns on the extraction calls
SO THAT I do not shell out to `tar` for the common case

**Acceptance criteria:**
```
GIVEN a refused pattern or an out-of-range strip value
WHEN passed from Python or Node.js
THEN InvalidConfigurationError / INVALID_CONFIGURATION is raised with the setting named, as for exclude_pattern on create
```

## 3. Functional Requirements

### Selection and rewriting model

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL express entry selection as a typed, validated value (working name `EntrySelection`) holding zero or more include patterns and zero or more exclude patterns; the default selects every entry; the value SHALL be immutable after construction and built through the config builder | must |
| FR-002 | THE SYSTEM SHALL express path rewriting as a closed, `#[non_exhaustive]` enum (working name `PathRewrite`) with at least `Keep` (default) and `Strip(StripComponents)`; there SHALL be no `bool` flag and no `0` standing for "none" | must |
| FR-003 | `StripComponents` SHALL be a newtype that cannot hold zero or a value above the destination's maximum path depth; runtime values (CLI, Python, Node) SHALL enter through one `limit.rs`-style boundary function that refuses `0`, negatives, non-integers and out-of-range values as `InvalidConfiguration` naming the setting | must |
| FR-004 | Selection patterns SHALL be the same typed pattern value and the same parser as the creation exclude patterns (one grammar, one `TryFrom<&str>`, one `Display`); a refused shape SHALL be refused at construction with `InvalidConfiguration` and the pattern named; no unparsed string SHALL be stored | must |
| FR-005 | WHEN an entry is tested against a selection, THE SYSTEM SHALL match the pattern against the archive entry path after the same normalization landing uses (`./`, leading `/`, `\` separators and drive prefixes handled as extraction does) and before any stripping; matching SHALL compare raw path component bytes, so a non-UTF-8 name is matched, not skipped | must |
| FR-006 | An entry SHALL be selected if and only if it matches at least one include pattern (or there are none) and matches no exclude pattern; an exclude pattern SHALL always win; a `Path` pattern SHALL select the named entry and its subtree | must |
| FR-007 | Selection SHALL apply to every entry kind (file, directory, symlink, hardlink), not only regular files as the extension allowlist does; the allowlist SHALL keep applying, after selection, to the regular files that remain | must |

### Order of operations and validation

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | THE SYSTEM SHALL process each entry in this fixed order: validate the original archive path as today (`SafePath`: traversal, absolute, banned components, depth, length, reserved names, placement through existing links), then selection, then stripping, then validation of the rewritten path, then the extension allowlist, then quota | must |
| FR-011 | WHEN an entry is not selected but its original path is unsafe (`../x.bin`, or below an existing file or dangling symlink), THE SYSTEM SHALL refuse it, not skip it, as the allowlist does today ([[002-format-handlers/spec]] FR-054) | must |
| FR-012 | THE SYSTEM SHALL build the landing path of a rewritten entry only through the validated path constructor (`SafePath`); no code path SHALL hand a format handler, a sink or the host a stripped name that did not pass validation, so the failure mode "validated name, then stripped" is unrepresentable in the types | must |
| FR-013 | Stripping SHALL count components of the normalized path; the leading `./` and the root or drive prefix of an absolute name (when `allow_absolute_paths` is on) SHALL NOT count as components | must |
| FR-014 | WHEN stripping leaves no component (an entry with N or fewer components, `top/` with strip 1, a name that becomes empty or `.`), THE SYSTEM SHALL skip the entry, count it as stripped away, perform no write and create no directory for it, and SHALL NOT treat the destination root as an entry's landing | must |
| FR-015 | WHEN the original path validates but the rewritten path does not (a re-check failure), THE SYSTEM SHALL refuse it with the typed error validation would raise for that name on its own | must |
| FR-016 | THE SYSTEM SHALL apply the same ordered rules in TAR (all codecs), ZIP and 7z, and in every destination (`HostTarget`, `MemorySink`, caller-owned `EntrySink`) | must |

### Collisions

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | WHEN two entries map to one landing path after rewriting, THE SYSTEM SHALL apply the existing duplicate rules unchanged: first entry wins and the later one is skipped and counted as a duplicate under `skip_duplicates = true`; an error under `skip_duplicates = false`; a later file replaces an earlier one under `--force`; and the existing refusals (file over directory, symlink over file or link, hardlink over anything) | must |
| FR-021 | Collision detection SHALL operate on the landing path under the destination's `PathModel` (case-insensitive component comparison for `Portable`), so `a/X` and `b/x` collide whenever the destination would treat them as one name | must |
| FR-022 | THE SYSTEM SHALL decide collisions on the rewritten path, never on the original, in `extract`, `list`'s landing projection and `verify` alike, so all three agree on which entry "wins" | must |

### Links

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | THE SYSTEM SHALL NOT rewrite symlink target text; a symlink SHALL be validated at its rewritten landing with its original target, so a link whose target resolved inside the archive only because of the stripped prefix (`top/link -> ../other/x`, strip 1) is refused as `SymlinkEscape`, never silently re-pointed | must |
| FR-031 | A hardlink target is an archive entry path; THE SYSTEM SHALL map it through the same selection and rewriting as entry names, and SHALL validate the mapped target as a `SafePath` | must |
| FR-032 | WHEN a hardlink's target is not selected, is stripped away, or is not extracted for any other reason, THE SYSTEM SHALL refuse the hardlink with a typed error naming the link and its target; it SHALL NOT create a dangling hardlink, a copy of data it did not extract, or a link to a path outside the extraction | must |
| FR-033 | In-archive link projection (`VirtualTree::project_landing`) and placement checks SHALL run on rewritten landing paths, so an entry placed beneath a symlink is judged where it would really land | must |

### Quotas, skips and reporting

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | An entry skipped by selection or stripping SHALL NOT be charged to `max_total_size` or `max_file_size`, SHALL create no directory, and SHALL be counted in `files_skipped`, whatever the destination state; it SHALL be charged to `max_file_count` exactly as an allowlist-skipped entry is (see #831, #846) | must |
| FR-041 | `SkipKind` SHALL gain distinct kinds for "not selected" and "stripped away" (working names `NotSelected`, `StrippedAway`), so `ExtractionReport::skipped`, CLI `--json` `skipped_by_kind` and both bindings can tell them apart from `Duplicate` and `ExtensionNotAllowed` | must |
| FR-042 | WHEN a compressed TAR is extracted, THE SYSTEM SHALL bound the decode of entries skipped by selection or stripping exactly as it bounds allowlist and duplicate skips: past `max_file_size` and `max_total_size`, skipped data SHALL NOT decode to more than `max_compression_ratio` times the compressed input read so far, else `ZipBomb` with scope `SkippedEntries` ([[002-format-handlers/spec]] FR-053, #863); an archive that extracts without a selection SHALL NOT be refused because of it | must |
| FR-043 | WHEN an `include` pattern matches no entry in the whole archive, THE SYSTEM SHALL fail with a typed error naming every unmatched pattern; the error SHALL carry the partial outcome like other late errors | must |
| FR-044 | An exclude pattern that matches nothing SHALL NOT be an error | must |
| FR-045 | Progress callbacks SHALL report skipped entries (selected-out or stripped) as skipped, not as processed, and the entry counts the callback sees SHALL stay consistent with `ExtractionReport` | should |

### `list` and `verify`

| ID | Requirement | Priority |
|----|------------|----------|
| FR-050 | `ListRequest` and `VerifyRequest` SHALL accept the same selection and rewrite value as extraction and SHALL interpret it with the same code; there SHALL be no second implementation of matching or stripping | must |
| FR-051 | `ArchiveManifest::landing_paths` and `landings` SHALL project through the selection and rewrite: entries not selected and entries stripped away SHALL be omitted, and every other landing SHALL be the rewritten path ([[019-verify-and-list-model/spec]] FR-060) | must |
| FR-052 | `verify` SHALL report as issues every refusal `extract` raises for the same selection (traversal after stripping, link escape, hardlink to a non-extracted target, collisions that fail, placement conflicts, over-long landings), so a passing `verify` with a selection never precedes a failing `extract` with it | must |
| FR-053 | `list` SHALL let the caller tell which entries a selection would extract and where each would land (working shape: a typed per-entry disposition in the manifest or on a landing iterator; the plan decides), and SHALL still charge every scanned entry to `max_file_count` | must |
| FR-054 | `verify` SHALL keep validating the original path of every entry, selected or not, as `extract` does (FR-011); unselected entries SHALL NOT produce link, placement or collision findings of their own | must |

### Flatten

| ID | Requirement | Priority |
|----|------------|----------|
| FR-060 | `PathRewrite` SHOULD offer a `Flatten` variant that lands each regular file under the destination root by its final component only; it SHALL be mutually exclusive with `Strip` by construction (one enum, not two fields) | should |
| FR-061 | Under `Flatten`, a collision SHALL be detected on the final component under the destination's `PathModel` (Unicode case-folded comparison, as FR-021 requires for `Portable`) and SHALL follow FR-020; the plan SHALL state how the reported skip distinguishes a flatten collision | should |
| FR-062 | Under `Flatten`, directory entries SHALL be skipped and counted; symlink and hardlink entries SHALL NOT be created with a target that was written for the original layout (see Open Questions for skip versus refuse) | should |

### Surfaces

| ID | Requirement | Priority |
|----|------------|----------|
| FR-100 | THE CLI `extract`, `list` and `verify` SHALL take `--strip-components <N>`, repeatable `--include <PATTERN>` and repeatable `--exclude <PATTERN>`, parsed once after clap into the typed values; a refused pattern or value SHALL exit `1` with the JSON envelope (`setting` named) and write nothing | must |
| FR-101 | THE CLI SHALL NOT take positional member arguments in this spec (the positional `OUTPUT_DIR` already follows the archive; see Open Questions) | must |
| FR-102 | THE CLI `--json` output for `extract` SHALL expose the new skip kinds in `skipped_by_kind`, and its text output SHALL name the pattern or the strip that left entries out; `list` and `verify` JSON SHALL carry the disposition required by FR-053 | must |
| FR-103 | `extract --atomic` SHALL apply selection and rewrite inside the temporary tree, so only selected and rewritten entries are committed; an unmatched include pattern (FR-043) SHALL roll back and commit nothing | must |
| FR-104 | Python `extract_archive*` SHALL take `strip_components: int | None = None`, `include: Sequence[str] | None = None`, `exclude: Sequence[str] | None = None`; Node `extractArchive*` SHALL take the same in its options object (`stripComponents`, `include`, `exclude`); both SHALL only map types and parse through the core boundary functions, with errors built from the single typed `ArchiveError::into_ffi_message()` | must |
| FR-105 | Python and Node SHALL document the order of operations (FR-010) and that matching is on the pre-strip path | must |
| FR-106 | The `skills/exarch-cli/SKILL.md` skill SHALL be updated in the same change, verified against the running binary | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Selection, stripping and flattening are not security boundaries and SHALL add no way to produce an unvalidated landing: the only constructor of a landing path is the validated one (FR-012), proven by types, not by a comment or a test |
| NFR-002 | Security | An archive that extracts without a selection and is refused under selection SHALL be refused with the typed error of its cause, never with a generic I/O error; the new feature SHALL NOT be able to turn a refused entry into an accepted one (a refused original path stays refused under any selection) |
| NFR-003 | Security | Bindings add no security logic: type mapping, error conversion and boundary validation (range of an integer, pattern parse) only |
| NFR-004 | Performance | An entry that selection leaves out SHALL cost no write, no hash, no per-entry allocation beyond what the allowlist skip costs today, and no extra decode: ZIP and non-solid 7z skip an unselected entry without decoding its data; a compressed TAR must decode the stream to reach the next header (no seek in gzip, bzip2, xz or zstd) but SHALL discard the bytes through the ratio-bounded skip path (FR-042), not copy them |
| NFR-005 | Performance | THE SYSTEM SHALL scan the whole archive even when every named entry has been found: the rest of the archive is still validated (hidden entries, ambiguous TAR headers, ZIP structure), because `verify && extract` must mean the same archive was judged. An opt-in early exit is an open question, not a default |
| NFR-006 | Performance | With the default selection (`All`) and `Keep`, extraction throughput SHALL NOT regress by more than 10% against the previous baseline in `.local/testing/benchmarks.md` (constitution VI); the unselected path SHALL be within 10% of the allowlist-skip path on the same fixture |
| NFR-007 | Compatibility | Defaults SHALL leave every existing extraction byte-for-byte unchanged. New `ExtractionOptions`/config fields, `SkipKind` variants and request methods are additive on `#[non_exhaustive]` types; the CHANGELOG records the new public items |
| NFR-008 | Determinism | Given the same archive and the same selection, `extract`, `list`, `verify` and every sink SHALL produce the same set of landings and the same refusals, in the same order of precedence |
| NFR-009 | Maintainability | One matcher and one rewrite function SHALL serve all formats and all three operations (DRY); format handlers SHALL call it through the existing per-entry gate and SHALL NOT embed their own copy |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `EntrySelection` (working) | Validated include and exclude pattern lists; default selects everything | `include`, `exclude`; `selects(&NormalizedPath) -> Selected` |
| `EntryPattern` (working; shared with the creation `ExcludePattern`) | One parsed pattern from the create grammar | `Exact`, `Prefix`, `Suffix`, `Path`; `TryFrom<&str>`, `Display` |
| `PathRewrite` (working) | Closed enum for how a validated path becomes a landing | `Keep`, `Strip(StripComponents)`, `Flatten` |
| `StripComponents` (working) | Newtype: 1 up to the maximum path depth; never zero | boundary parse from `u64`/`i64` |
| `Selected` (working) | Result of testing an entry: extract it, or leave it out for a stated reason | `Extract`, `Skip(NotSelected \| StrippedAway)` |
| `SkipKind` | Existing `#[non_exhaustive]` enum of skip reasons | adds `NotSelected`, `StrippedAway` |
| `SelectionError` (working) | Typed error for an include pattern that matched nothing, a hardlink whose target was not extracted | unmatched patterns; link and target paths |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Strip 1 and an entry `top/` | Skipped, counted as stripped away; destination root untouched (FR-014) |
| Strip 1 and a top-level file `README` | Skipped, counted as stripped away, not an error (as `tar --strip-components` does); see Open Questions on a strict mode |
| Strip 2 and an entry `a/b` (exactly N components) | Skipped as stripped away |
| Strip N larger than any entry | Every entry skipped; extraction reports success with nothing extracted; a boundary value above max path depth is refused at construction |
| `top/../x` and strip 1 | Refused as `PathTraversal` by validation of the original name, before selection and stripping (FR-010) |
| `./top/x` and strip 1 | `./` does not count; lands at `x` (FR-013) |
| ZIP entry `top\x` | Normalized to `top/x` before matching and stripping |
| Absolute `/top/x` with `allow_absolute_paths`, strip 1 | Root prefix not counted; lands at `x` |
| `a/x` and `b/x` with strip 1 | Both map to `x`; first wins and the second is a counted duplicate by default; `--force` replaces; `skip_duplicates = false` fails (FR-020) |
| `a/X` and `b/x`, strip 1, `Portable` model | Collide (FR-021) |
| Directory entry `top/` stripped away, files below it remain | Files land under the root; implicit parent directories are created as extraction does today |
| Select `top/sub/file` only | `top/sub` is created as an implicit parent; explicit directory entries of the ancestors that are not selected are not applied, so their recorded modes are not set |
| Symlink `top/link -> ../other/x`, strip 1 | Refused as `SymlinkEscape`; target text is never rewritten (FR-030) |
| Symlink `top/bin/t -> ../lib/x`, strip 1 | Lands as `bin/t -> ../lib/x`, resolves to `lib/x` inside the destination; accepted if `allow_symlinks` |
| Hardlink `top/l` to `top/orig`, only `top/l` included | Refused; target not extracted (FR-032) |
| Hardlink `top/l` to `top/orig`, strip 1, both selected | `l` hardlinks `orig` at the destination |
| Hardlink whose target is exactly the stripped wrapper `top` | Refused: target stripped away |
| Include `a/b` matches no entry | Typed error after the scan, naming the pattern; `--atomic` commits nothing (FR-043, FR-103) |
| Exclude matches nothing | No error (FR-044) |
| Include of bare name `README` | Matches a component named `README` at any depth, as a create exclude does; use `Path` form (`top/README`) to anchor |
| Unselected entry with a path under an existing file or dangling symlink | Refused, not skipped (FR-011) |
| Compressed TAR whose unselected entries inflate far past the ratio | `ZipBomb`, scope `skipped entries` (FR-042) |
| Entry whose data is skipped in a solid 7z block | The block is still decoded as a whole (needs `allow_solid_archives`); skipped entry data is not written |
| `--atomic --force` over an existing destination with a partial selection | The swap replaces the whole destination with the selected subset, as the swap does today for any extraction; see Open Questions |
| `verify` with a selection on an archive `extract` would refuse | `verify` reports the refusal (FR-052) |
| `list` with a selection | Every scanned entry is charged to `max_file_count`; the caller can see which entries extract (FR-053) |
| Selection together with `--allowed-extensions` | Selection first, then the allowlist on the remaining regular files; an entry out for either reason is counted once, under the first reason that applied |
| Non-UTF-8 entry name and a pattern | Matched by raw bytes (FR-005) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Differential test against `bsdtar` and GNU `tar` on a crafted corpus (wrapper directory, `./` prefixes, N or fewer components, hardlinks, symlinks, duplicate names after stripping): set of extracted files under `--strip-components N` | identical to `tar`, except where this spec deliberately differs and the plan names it |
| SC-002 | Differential test against `cpython` `tarfile` `members=` and `node-tar` `strip`/`filter` on the same corpus | same extracted set for the same selection |
| SC-003 | Landing parity: for every fixture and selection, the landings `extract` writes equal `landing_paths` output and every `extract` refusal is a `verify` issue (TAR, ZIP, 7z, `MemorySink`) | 100%, as differential tests |
| SC-004 | Quota parity with the allowlist: a selected-out entry is not charged to `max_total_size`, `max_file_size`, creates no directory, counts toward `max_file_count` (regression tests mirroring #831, #846) | pass for TAR, ZIP, 7z |
| SC-005 | Decode bound: `.tar.gz` of 200 MiB of zeros, include of one small file, default limits | `ZipBomb` scope `skipped entries`, as the allowlist fixture; passes with the ratio raised |
| SC-006 | Path-safety regression: every existing traversal, symlink and hardlink fixture, re-run under strip 1 and under an include, | never accepts a name the plain run refuses |
| SC-007 | Fuzzing: the existing extraction fuzz target gains a selection and strip input | no panic, no write outside the destination, in the project's standard fuzz duration |
| SC-008 | Throughput | default-path regression at most 10%; unselected path within 10% of the allowlist skip on the same fixture |
| SC-009 | Binding parity: the same selection yields the same extracted set and the same typed error in CLI, Python and Node tests | pass |

## 8. Agent Boundaries

### Always (without asking)
- Run `rust-security-maintenance` after any change; this feature touches path validation, link handling and quotas
- Live-test the critical paths of `continuous-improvement.md` (path traversal, symlink and hardlink validation, quota and ratio, `--atomic`) under strip and selection before a PR
- Reuse the create pattern parser and the existing duplicate, skip and landing machinery instead of adding parallel ones
- Keep all logic in `exarch-core`; bindings only map types
- Update `specs/` through the `rust-agents:sdd` agent in a dedicated worktree, `CHANGELOG.md`, doc comments with `# Examples`, and `skills/exarch-cli/SKILL.md`

### Ask First
- Adding a glob syntax beyond the create grammar
- A caller-supplied filter callback
- An overwrite-policy enum
- Early termination of the archive scan
- Rewriting symlink targets
- Positional member arguments on the CLI

### Never
- Build a landing path from a stripped or flattened string without passing it through `SafePath` validation
- Strip, flatten or select before the original path has been validated
- Represent "no stripping" as `0` or any rewrite choice as a `bool`
- Create a hardlink to a target that was not extracted
- Charge or decode skipped entries differently from the extension allowlist
- Let `verify` or `list` use a different matcher than `extract`
- Add security logic to a binding

## 9. Open Questions

- [NEEDS CLARIFICATION: Where does the value live? `allowed_extensions` sits in `SecurityConfig`, and `ListRequest`/`VerifyRequest` are built from a `SecurityConfig` only, so the simplest way for all three operations to share it is a `SecurityConfig` field. But selection is an operational choice, not a security limit, and `ExtractionOptions` is not passed to `list` or `verify`. Alternatives: a `SecurityConfig` field, or a new value passed to all three requests.]
- [NEEDS CLARIFICATION: Matching is specified on the original (pre-strip) path, as `tar`, `bsdtar` and `node-tar`'s `filter` do. `tar --strip-components=1 -x project/README` therefore needs the unstripped name. Is that the intended default for the CLI help and the bindings, or should a separate post-strip matcher exist?]
- [NEEDS CLARIFICATION: Should an include pattern that matches nothing be an error by default (GNU `tar` exits 2: "Not found in archive")? FR-043 says yes. In a non-atomic extraction the error arrives after earlier entries were written; is a cheap pre-pass (`ListRequest::for_extraction` already keeps the decode) wanted to fail before any write?]
- [NEEDS CLARIFICATION: Should a regular file whose name is consumed entirely by stripping (`README` at top level with strip 1) be a counted skip (FR-014, as `tar` does) or an optional strict refusal, since silently dropping a file the caller probably wanted is a surprise?]
- [NEEDS CLARIFICATION: Do `./` and the root count as a component? bsdtar and GNU `tar` differ for names like `./top/x`. FR-013 chooses "do not count"; confirm against the differential corpus (SC-001) and record the deliberate difference.]
- [NEEDS CLARIFICATION: Hardlink to an unselected or stripped target: refuse (FR-032, matches GNU `tar`'s failure) or select the target implicitly (closure)? Closure is friendlier but changes what the caller asked for and what is charged to quotas.]
- [NEEDS CLARIFICATION: `--atomic --force` swaps the whole destination, so extracting a subset replaces an existing directory with only that subset and deletes everything else in it. Refuse the combination of `--atomic --force` with a non-default selection or strip, or document it as is?]
- [NEEDS CLARIFICATION: Flatten in this spec or its own? It brings collision detection with Unicode case folding (safe_unzip does this) and the link question below. FR-060 to FR-062 are `should`, so the plan can split it out.]
- [NEEDS CLARIFICATION: Under `Flatten`, are symlink and hardlink entries skipped (counted) or refused? `unzip -j` and `safe_unzip` handle only files; a skip loses content silently, a refusal makes flatten unusable on archives with any link.]
- [NEEDS CLARIFICATION: Should a flatten collision, or a stripped-name collision, be an error instead of "first wins" by default? Under strip a collision is rare; under flatten it is the normal failure and silent first-wins is data loss. Today's `skip_duplicates = true` default would apply (FR-020), but an overwrite-policy enum is out of scope.]
- [NEEDS CLARIFICATION: Pattern case sensitivity. The create matcher compares case-sensitively while banned components compare case-insensitively. Should extraction patterns be case-sensitive on every host (current proposal) or follow the destination's `PathModel`?]
- [NEEDS CLARIFICATION: Shape of the `list` disposition (FR-053): a new typed field on `ArchiveEntry`, a separate iterator next to `landings`, or both. This also decides whether `ArchiveManifest::total_size()` counts selected files only.]
- [NEEDS CLARIFICATION: With `verify --check-integrity`, should the payload of unselected entries be decoded and checked (the gate then says the whole archive is intact) or skipped (cheaper, and the gate only speaks for what `extract` writes)?]
- [NEEDS CLARIFICATION: CLI shape. Positional members (`tar` style) conflict with the existing positional `OUTPUT_DIR`; `-C` would have to be introduced. This spec uses `--include`/`--exclude`/`--strip-components`; is a `-C`-style member form wanted later?]
- [NEEDS CLARIFICATION: Is the selection-skip charged to `max_file_count` in `extract` today the same way `list` charges it? FR-040 says "exactly as an allowlist-skipped entry"; the plan must read the current extract-side behavior and align `list`, `verify` and `extract` if they differ.]
- [NEEDS CLARIFICATION: A filter callback for the bindings (as `tarfile`'s `filter`, `node-tar`'s `filter` and `safe_unzip` offer) cannot be modeled by `verify`, so it would break the truthful-gate property. Keep it out for good, or allow it in `extract` only with `verify` refusing to claim parity?]

## 10. See Also

- [[constitution]] — project principles (typed validation pipeline, bindings map types only, quota permits)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `SafePath`, `ValidatorCore`, typed proofs
- [[002-format-handlers/spec]] — extension allowlist order (FR-054), skipped-entry decode bound (FR-053)
- [[003-config-api/spec]] — config builders and `limit.rs` boundary parsing
- [[005-cli/spec]] — `extract`, `list`, `verify` flags and exit codes
- [[015-atomic-force-destination-swap-hardening/spec]] — `--atomic --force` swap
- [[019-verify-and-list-model/spec]] — `landing_paths`, `landings`, verify models extraction (FR-060, FR-061)
- [[020-reader-sink-and-in-memory-api/spec]] — sinks run the same gates
- [[021-create-staging-and-output-policy/spec]] — the pattern grammar (`ExcludePattern`) reused here; create `--strip-prefix`
- [python/cpython `tarfile`](https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractall) — `extractall(members=...)` and the `filter` callable
- [PEP 706](https://peps.python.org/pep-0706/) — `tarfile` extraction filters
- [npm/node-tar](https://github.com/npm/node-tar) — `extract({ strip, filter, file list })`
- [tenuo-ai/safe_unzip](https://github.com/tenuo-ai/safe_unzip) — v0.2.0 (2026-10-26): `only()`, `include_glob`/`exclude_glob`, filter callback, `junk_paths` with Unicode case-folded collision detection, `Skip`/`Overwrite`/`Error` overwrite policies
- [GNU tar manual](https://www.gnu.org/software/tar/manual/tar.html) — `--strip-components`, member arguments, `--wildcards`, `--exclude`
- [bsdtar manual](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1) — `--strip-components`, `--include`, `--exclude`
- Closed issues #831, #846 (allowlist order and charge), #863 (skipped-entry decode bound in compressed TAR)
