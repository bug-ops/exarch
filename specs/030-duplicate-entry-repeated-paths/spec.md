---
aliases:
  - Repeated Paths
  - Refuse Repeated Paths
  - In-archive repeat policy
tags:
  - sdd
  - spec
  - security/parser-differential
  - extraction/duplicates
created: 2026-11-14
updated: 2026-11-15
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[022-extract-entry-selection/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[003-config-api/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
---

# Feature: Opt-in Refusal of Repeated Archive Paths

> [!info] Metadata
> **Subsystem**: `exarch-core` (`security`, `formats`, `inspection`, `error`), surfaced by `exarch-cli`, `exarch-python`, `exarch-node`
> **Issue**: #1201 (batch PR #1230 branch `feat/1230-batch-11-issues`)
> **Origin**: tar-minefield parity run (research finding, P2). Suite commit e3060bda2a54631c37d088914a24dddac34e7360.
> **Decision**: direction A, an opt-in reject mode (user decision, 2026-11-15). The default stays first-wins.
> **Status**: implemented in the batch PR #1230, unreleased. Deviations are listed in section 9.

> [!abstract]
> When an archive names one path more than once, exarch keeps the first entry and exits 0, while the reference implementations of the minefield matrix keep the last. A checker that reads the archive with another tool can see different content from what exarch installs. This spec adds `RepeatedPaths::Refuse`, an opt-in policy on `SecurityConfig` under which such an archive is refused with a typed `Violation::RepeatedPath`. Last-wins and a status-quo signal were considered and not chosen.

## 1. Overview

### Problem Statement

On the S-series (order and state) cases of the tar-minefield suite exarch is the outlier: it keeps the first copy and the other implementations keep the last. Nothing is written outside the destination in any case, so this is a parser differential, not a containment failure.

| Case | Archive content | exarch (default) | Other implementations |
|------|-----------------|------------------|-----------------------|
| S07 | file `a` twice, `first` then `last` | extracts `first` | most extract `last` |
| S09 | identical duplicate | extracts the one file | all but one extract the same tree |
| S10 | symlink `a`, then file `a` | keeps the symlink | GNU tar, bsdtar and others replace the link |
| S14 | symlink `a`, then directory `a` | keeps the symlink | mixed: replace or reject |
| S15 | file `a`, file `b`, hardlink `a` to `b` | keeps the original `a` | GNU tar and bsdtar link `a` to `b` |
| S17 | hardlink `a` to `b`, then file `a` | keeps the hardlink-made `a` | others replace it |

First-wins is deliberate and documented ([[019-verify-and-list-model/spec]] FR-043, [[022-extract-entry-selection/plan]] Q10): default `ExistingFiles::Skip` and `Refuse` skip an in-archive repeat, and only `Overwrite` makes the last copy win. The skip is reported (`skipped_by_kind.duplicate`) but the status is success.

### Why direction A

| Direction | Outcome | Decision |
|-----------|---------|----------|
| A. Opt-in refusal | Removes the differential by refusing; reuses the run record and the list landing model | chosen |
| B. Last-wins for in-archive repeats | Replacing a run-made symlink, hardlink or directory mid-run needs recursive removal and hardlink re-targeting inside the containment layer, and changes default output | not chosen |
| C. Keep first-wins with a stronger signal | Keeps the differential | not chosen |

### Goal

A caller who opts in gets a typed, distinct refusal for any archive whose entries land on one path more than once, identically on extract (host and sink), `list` and `verify`, without changing any result for callers who do not opt in.

### Out of Scope

- Last-wins semantics (direction B) and a stronger default signal (direction C).
- A content comparison: identical repeats (S09) are refused too.
- Changing the default (`KeepFirst`) or the meaning of `ExistingFiles` for content that existed before the run.
- Archive creation duplicate handling.
- Making the refusal all-or-nothing by itself: that is `Staging::Atomic` (FR-009).

## 2. User Stories

### US-001: Reject ambiguous archives

AS A security-conscious integrator (scanner, installer, CI step)
I WANT extraction to refuse an archive that repeats a path, with a distinct typed error
SO THAT the extracted tree cannot differ from what my reviewer saw with another tool.

**Acceptance criteria:**
```
GIVEN a 7z archive, or a ZIP with an exact repeated name, that repeats file "a"
WHEN extraction runs with RepeatedPaths::Refuse
THEN it fails with a RepeatedPath refusal naming "a"
AND nothing is written to the destination
```
```
GIVEN a tar archive that repeats file "a"
WHEN extraction runs with RepeatedPaths::Refuse and Staging::Atomic
THEN it fails with a RepeatedPath refusal and the destination is unchanged
```

### US-002: Default behavior is unchanged

AS A user who does not opt in
I WANT today's first-wins result, report and exit status
SO THAT nothing changes for existing callers.

**Acceptance criteria:**
```
GIVEN an archive that repeats a path and the default configuration
WHEN extraction completes
THEN the first copy is kept, the repeat is counted as a duplicate skip, and the exit status is 0
```

### US-003: Checker and extractor agree

AS A caller who runs `verify` or `list` before extracting
I WANT both to report the repeat as extraction would refuse it
SO THAT a pre-check cannot pass an archive that extraction refuses.

**Acceptance criteria:**
```
GIVEN RepeatedPaths::Refuse and an archive that repeats a path
WHEN list runs
THEN the later entry has disposition refuse with the RepeatedPath reason
AND verify reports a finding for it
```

## 3. Functional Requirements

### FR-001

THE SYSTEM SHALL provide `RepeatedPaths` as a typed, `#[non_exhaustive]` enum with `KeepFirst` (default) and `Refuse`, set on `SecurityConfig` (builder `with_repeated_paths`) so that extract, list, verify and the in-memory sinks all read it. It SHALL NOT be a `bool`.

**Priority**: must

### FR-002

WHEN `repeats` is `Refuse` and an entry's landing holds an occupant that this run made THE SYSTEM SHALL refuse the entry with `ArchiveError::SecurityViolation { kind: Violation::RepeatedPath { path, earlier, later } }` under every `ExistingFiles` mode, except a directory entry over a directory (which also covers implicit parent directories).

**Priority**: must

### FR-003

`Violation::RepeatedPath` SHALL carry the repeated path (`Box<str>`) and the kinds of both entries (`ManifestEntryType`, `earlier` and `later`). On the host `earlier` maps the occupant kind (File, Directory, Symlink; an occupant made by a hardlink is File). Its machine code SHALL be `SECURITY_VIOLATION` with sub-code `REPEATED_PATH`, relaxable by `PolicySetting::RepeatedPaths`.

**Priority**: must

### FR-004

WHEN `repeats` is `Refuse` THE SYSTEM SHALL decide the maker of an occupant with a tri-state result (`Run`, `Foreign`, `Unknown`) and SHALL fail closed:

- `Run`: the key is in an unsaturated run record: FR-002 applies.
- `Foreign`: an identity key that is not in an unsaturated record: the configured `ExistingFiles` decides, as today.
- `Unknown`: the record is saturated, the identity lookup failed, or a path-spelled key (FAT, exFAT, Windows without `FileIdInfo`) is not in the record: the entry is refused with `ArchiveError::DestinationOccupied { by: OccupiedBy::Existing }` under every `ExistingFiles` mode, including `Skip` and `Overwrite`.

**Priority**: must

### FR-005

WHEN `repeats` is `Refuse` THE SYSTEM SHALL size the run record `Full` under every `ExistingFiles` mode, through one crate-private `OccupantPolicy { existing, repeats }` that also owns the occupant decision at every production site (tar, zip, 7z host and the sink).

**Priority**: must

### FR-006

WHEN `repeats` is `Refuse` THE SYSTEM SHALL scan a 7z archive for a landing claimed twice before any write, so a 7z repeat writes nothing.

**Priority**: must

### FR-007

ZIP repeats SHALL be handled as follows. The `zip` crate dedupes exact names when it opens the archive, so exarch enforces the finding itself:

| Case | `KeepFirst` (default) | `Refuse` |
|------|-----------------------|----------|
| Exact repeated name, `zip_consistency` Enforce | `ZipInconsistency::DuplicateName` (unchanged) | `Violation::RepeatedPath`, before any write |
| Exact repeated name, `zip_consistency` Ignore | collapses silently (status quo, documented) | `Violation::RepeatedPath`, before any write |
| Landing collision (case variant, strip or rewrite) | duplicate skip | `Violation::RepeatedPath` |

Under `Refuse`, `verify` reports the same finding once, as `RepeatedPath`, under both `zip_consistency` policies (the structure finding it came from is not reported a second time). The `ZipInconsistency` variant shape is unchanged.

**Priority**: must

### FR-008

WHEN `repeats` is `Refuse` THE SYSTEM SHALL make `list` report the later landing as `refuse` with the same error and `verify` report an issue derived from it, through the shared `RECORD_CAP` and the `RunKeys` model. For a landing the list model cannot prove unique (cap passed, or a non-matching spelling under `VolumeIdentity::LandingPaths`) the disposition is `refuse` with `DestinationOccupied`, as in FR-004.

**Priority**: must

### FR-009

THE documentation of every front end (Rust docs, `exarch.pyi`, `index.d.ts`, the CLI skill) SHALL state that `Refuse` combined with `Staging::Atomic` is the all-or-nothing recipe: nothing is written for 7z (pre-pass) or for ZIP exact names; for tar and for landing collisions the first copy stays unless the run is atomic.

**Priority**: must

### FR-010

WHEN `repeats` is `KeepFirst` THE SYSTEM SHALL behave byte-identically to today for every archive.

**Priority**: must

### FR-011

THE CLI SHALL accept `--repeated-paths <keep-first|refuse>` on `extract`, `list` and `verify`, Python SHALL expose `SecurityConfig.with_repeated_paths("refuse")` and Node `repeatedPaths: 'keep_first' | 'refuse'` (snake_case closed-enum strings). A refusal SHALL carry the hint `--repeated-paths keep-first`.

**Priority**: must

## 4. Non-Functional Requirements

### NFR-SEC-001

The policy SHALL NOT weaken any existing containment guarantee: traversal, symlink and hardlink escape, quota and compression-ratio checks apply to every copy of a repeated path. The minefield baseline (nothing written outside the destination, no crash, no timeout) SHALL hold.

### NFR-SEC-002

A selection (spec 022, 023) that deselects an earlier copy means that copy is never a repeat; a strip or rewrite that makes two names collide is a repeat. Detection is occupancy-based, on the resolved destination path, so PAX and GNU extended-header renames are covered.

### NFR-REL-001

`tests/dispositions_match_extraction.rs` SHALL pin agreement of host, sink, `list` and `verify` per entry under `Refuse`, while the host record is unsaturated and every identity lookup succeeds. The four do not saturate at the same point (the host counts implicit parent directories, list counts new placements only, `RunKeys::Identity` keeps no keys), so past the host cap and on a failed identity lookup extraction fails closed where `list` may still report `skip`. This divergence is documented, needs more landings than the default `max_file_count` allows, and is not claimed equal.

### NFR-COM-001

`ExistingFiles` keeps its meaning. A documented consequence: under `Refuse`, a pre-existing occupant on a volume without file identity is refused, not skipped.

### NFR-COM-002

Output, exit status and JSON for archives that do not repeat a path, and for every archive under `KeepFirst`, are unchanged. `skills/exarch-cli/SKILL.md` documents the flag and the ZIP table of FR-007.

### NFR-PERF-001

`KeepFirst` throughput regresses by at most 10% against the pre-change baseline on the `exarch-core` benchmarks; the `Refuse` cost is paid only on opt-in and only for an occupied landing.

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `RepeatedPaths` | Policy on `SecurityConfig` | `KeepFirst` (default), `Refuse` |
| `OccupantPolicy` | Crate-private pair deciding occupants and record budget | `existing`, `repeats` |
| `Maker` | Crate-private tri-state result for an occupant | `Run`, `Foreign`, `Unknown` |
| `Violation::RepeatedPath` | Typed refusal | `path`, `earlier`, `later` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Identical duplicate (S09) | Refused under `Refuse`; no content comparison |
| File then file, different content (S07) | `RepeatedPath` under `Refuse`; first kept under `KeepFirst` |
| Symlink then file, symlink then directory, hardlink then file (S10, S14, S17) | `RepeatedPath`; the link is never followed or replaced |
| File, file, hardlink over the first (S15) | `RepeatedPath` |
| Directory over directory, implicit parents | Not a repeat |
| Earlier copy filtered out by selection | Not a repeat |
| Pre-existing destination file, archive names it once | `ExistingFiles` decides; a `Foreign` occupant is not a repeat |
| Pre-existing occupant, saturated record or failed identity lookup | `DestinationOccupied { by: Existing }` under every mode |
| Pre-existing occupant on a volume without file identity | Refused under `Refuse`, not skipped (documented) |
| ZIP exact repeated name | `RepeatedPath` before any write, whatever `zip_consistency` says |
| 7z repeated landing | `RepeatedPath` before any write |
| tar repeated path, non-atomic | `RepeatedPath` at the repeat; the first copy stays (partial extraction) |
| tar repeated path, `Staging::Atomic` | `RepeatedPath`; destination unchanged |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | One regression test per minefield case S07, S09, S10, S14, S15, S17, built in-test and citing suite commit e3060bda, in `crates/exarch-core/tests/repeated_paths.rs` | `Refuse` gives `RepeatedPath`; `KeepFirst` gives today's outcome; every `ExistingFiles` mode and the in-memory sink |
| SC-002 | Fail-closed causes: saturation (a `cfg(test)` cap), identity-lookup failure, path-keyed record; ZIP Refuse+Ignore writes nothing; Refuse+Skip with a foreign pre-existing file is still skipped | each pinned by a test |
| SC-003 | `dispositions_match_extraction.rs` under `Refuse` | host, sink, list and verify agree within NFR-REL-001 |
| SC-004 | Archives without a repeat, and every `KeepFirst` run | byte-identical result, exit status and JSON |
| SC-005 | Binding parity | `exarch-python/tests/test_repeated_paths.py`, `exarch-node/tests/repeated-paths.test.js`, CLI `exarch-cli/tests/repeated_paths.rs` |
| SC-006 | Minefield cases with a write outside the destination, crash or timeout | 0 |

## 8. Agent Boundaries

### Always (without asking)
- Run `rust-security-maintenance` after any code change.
- Keep all security logic in `exarch-core`; bindings map types and errors only.
- Encode policy and refusal as types, never booleans or strings.
- Update `skills/exarch-cli/SKILL.md` and verify claims against the running binary.

### Ask First
- Changing the default repeat behavior.
- Adding a dependency or changing CLI exit codes and `--json` `status` values.

### Never
- Weaken any path, symlink, hardlink, quota or ratio check.
- Replace or write through a symlink or hardlink to resolve a repeat.
- Put worst-case figures or private-advisory detail in public text.
- Change `workspace.package.version` in a feature PR.

## 9. Open Questions

None open. Resolved with the user on 2026-11-15: direction A, opt-in, default `KeepFirst`, setting on `SecurityConfig`, identical content refused, `verify` reports the repeat, `list` marks the later copy `refuse`, uniform refusal across formats (a forced ZIP duplicate is `RepeatedPath`).

### Deviations (approved by the lead during the batch)

| Requirement | Specified | Implemented |
|-------------|-----------|-------------|
| FR-003 | `earlier` and `later` are the real entry kinds | for a ZIP `DuplicateName` the finding carries no kinds, so both are taken from the name (a trailing `/` is a directory) and are equal |
| FR-009 | tar refuses at the repeat | the CLI list pass already marks a tar repeat `refuse`, yet extract writes the first copy and then fails (`PartialExtraction`); a pre-write refusal needs `--atomic` (documented) |
| NFR-REL-001 | agreement per entry | unchanged; past the host record cap and after a failed identity lookup extraction fails closed where `list` may report `skip` (documented) |
| SC-001 | S14 and S17 rows | the `KeepFirst` outcomes of S14 and S17 were re-checked against the base binary and the upstream archives and equal the table above |

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[019-verify-and-list-model/spec]] — FR-043 first entry wins, `is_run_duplicate`
- [[022-extract-entry-selection/plan]] — Q10
- [[017-zip-header-consistency/spec]] — `ZipInconsistency::DuplicateName`
- [[030-duplicate-entry-repeated-paths/plan]] — plan and Contracts
- `crates/exarch-core/tests/dispositions_match_extraction.rs` — agreement guard
- Issues #1201, #1179
- [haampie/tar-minefield](https://github.com/haampie/tar-minefield) — cases S07, S09, S10, S14, S15, S17
