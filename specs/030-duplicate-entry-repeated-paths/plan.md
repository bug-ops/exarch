---
aliases:
  - Repeated Paths Plan
tags:
  - sdd
  - plan
  - extraction/duplicates
created: 2026-11-15
status: ready
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: Opt-in Refusal of Repeated Archive Paths

> [!info] References
> **Spec**: [[spec]]. Issue #1201.

## 1. Architecture

### Approach

Reuse the existing run record (`OccupiedBy::Archive`, `created_here`) and the `LandingClaims` / `RunKeys` model of list, so no new detection machinery is added. A crate-private `OccupantPolicy { existing, repeats }` replaces `ExistingFiles::on_occupant` at every production site and also decides the record budget.

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|-------------------------|
| Direction | Opt-in `Refuse`, default `KeepFirst` | No change of default output; no recursive removal in the containment layer | Last-wins; signal only |
| Setting location | `SecurityConfig` | extract, list, verify and sinks all read it (precedent: `zip_consistency`, `selection`) | `ExtractionOptions`, a new `ExistingFiles` variant |
| Maker | Tri-state `Maker { Run, Foreign, Unknown }` next to `created_here` | Fail closed when the maker cannot be proven | Boolean `created_here` |
| Record budget | `OccupantPolicy::record_budget()` is `Full` under `Refuse` | A saturated record cannot prove a maker | Keep the per-mode budget |
| ZIP | Enforce the `DuplicateName` finding in `admit_structure` under `Refuse` and raise it as `RepeatedPath` | The zip crate dedupes names at open | Leave `DuplicateName` |

Budget wiring (3 sites): `formats/tar.rs`, `formats/zip.rs`, `formats/sevenz/mod.rs` replace `options.existing_files.record_budget()` with `OccupantPolicy::new(existing_files, repeated_paths).record_budget()`. The staged-run ledger is confirmed `Full`.

Production decision sites: `sink.rs`, `formats/common.rs` (2), `formats/target.rs`, `formats/sevenz/host.rs` (2). Tests in `formats/occupant.rs` follow.

## 2. Project Structure

```
crates/exarch-core/src/
├── formats/{occupant,common,target,run_record}.rs   # OccupantPolicy, Maker
├── formats/zip.rs (admit_structure), zip_structure.rs (duplicate pass)
├── formats/sevenz/host.rs                           # pre-pass refuses a twice-claimed landing
├── inspection/{landing,verify}.rs                   # RunKeys, RepeatedPath disposition and issue
├── error/violation.rs                               # Violation::RepeatedPath
└── config/                                          # RepeatedPaths, PolicySetting::RepeatedPaths
```

## 3. Data Model

```rust
#[non_exhaustive]
pub enum RepeatedPaths { KeepFirst, Refuse }

// Violation::RepeatedPath { path: Box<str>, earlier: ManifestEntryType, later: ManifestEntryType }
pub(crate) enum Maker { Run, Foreign, Unknown }
```

## 4. API Design

CLI `--repeated-paths <keep-first|refuse>` on extract, list and verify; Python `SecurityConfig.with_repeated_paths(str)` with an attribute and `.pyi` entry; Node `repeatedPaths` option with regenerated `index.d.ts`. Error JSON: `SECURITY_VIOLATION` / `REPEATED_PATH`.

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| spec 019 list/verify model | inbound | `RunKeys`, `RECORD_CAP` | disposition and issue derive from the same error |
| spec 017 ZIP consistency | inbound | `ZipInconsistency::DuplicateName` | forced under `Refuse`, raised as `RepeatedPath` |

## 6. Security

Error-only change under opt-in: no path is admitted that was refused before. No replacement, removal or re-targeting is introduced. Unknown makers refuse.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|-------------|-----------------|
| Unit | nextest | budget `Refuse` to `Full` under all three `ExistingFiles` values; saturation via a `cfg(test)` cap; identity-lookup failure; path-keyed record | each fail-closed cause |
| Integration | nextest | `repeated_paths.rs` S07, S09, S10, S14, S15, S17 under every mode and the sink; ZIP Refuse+Ignore; Refuse+Skip with a foreign file | all |
| Agreement | nextest | `dispositions_match_extraction.rs` under `Refuse` | per NFR-REL-001 |
| Bindings and CLI | pytest, node test, nextest | parity tests | option and error |

## 8. Performance Considerations

`KeepFirst` regression at most 10% against the baseline; the `creation` and `extraction` benches are compared.

## 9. Rollout Plan

Opt-in; CHANGELOG entry; skill update in the docs pass. Landing order in the batch: after the issues that own `host.rs`, `occupant.rs` and `target.rs` (#1230, #1232), before the encryption work that shares `formats/zip.rs` and `inspection/verify.rs`.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| Type safety | Compliant | enum policy, typed violation, tri-state maker |
| Security | Compliant | fail closed |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Host and list saturate at different points | med | low | documented divergence, needs more landings than the default file limit |
| Windows without file identity refuses a pre-existing occupant | low | med | documented; only under `Refuse` |

## 12. Contracts

| Item | Preconditions | Postconditions | Undefined behaviour |
|------|---------------|----------------|---------------------|
| `SecurityConfig::with_repeated_paths(Refuse)` | none | a later entry over a run-made occupant gives `RepeatedPath` (directory over directory exempt); an occupant with an unprovable maker gives `DestinationOccupied { by: Existing }` under every `ExistingFiles` mode; a ZIP exact-name repeat gives `RepeatedPath` before any write whatever `zip_consistency`; host, sink, list and verify agree per NFR-REL-001 | agreement past the host record cap and after a failed identity lookup is not claimed |
| `OccupantPolicy::record_budget()` | none | `Full` when `repeats == Refuse`, else the `existing` budget | none |
| `RunRecord::maker(dir, leaf, rel)` | called for an occupied landing | `Run`, `Foreign` or `Unknown` per spec FR-004 | none |

## See Also

- [[spec]]
- [[MOC-specs]]
