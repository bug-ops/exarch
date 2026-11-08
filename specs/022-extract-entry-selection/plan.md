---
aliases:
  - Extract Entry Selection Plan
tags:
  - sdd
  - plan
  - extraction
  - security
  - rust
created: 2026-11-06
status: implemented
related:
  - "[[spec]]"
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
---

# Implementation Plan: Extract Entry Selection and Path Stripping

> [!info] References
> **Spec**: [[spec]]
> **Tasks**: [[tasks]]
> **Origin**: #967, implemented in the #981 batch PR (track `core-selection`, then CLI, Python and Node W2 steps)
> **Basis**: architect handoff `2026-11-06T08-47-44` (Q1-Q16 defaults, approved by the user), `08-55-12` (`ExistingFiles::Refuse`), `08-57-00` (amendment), W0 freeze at `73d694b`

## 1. Resolved decisions

The spec's open questions are closed as follows. The spec carries the same answers in section 9.

| Q | Decision | Consequence for the plan |
|---|----------|--------------------------|
| Q1 | `SecurityConfig` gains the field `selection: EntrySelection`, which contains the `PathRewrite` | Extract, list, verify, `for_listing` and sinks read one value by construction; no request signature changes |
| Q2 | Matching runs on the normalized original path, before stripping (tar, bsdtar, node-tar semantics) | One `Selected` decision per entry, taken before the rewrite |
| Q3 | An include pattern that matches nothing fails after the full scan with a typed error naming every unmatched pattern, carrying `Partial`; `Atomic` rolls back; there is no pre-pass | A per-run pattern hit set; the error is raised at the end of the scan |
| Q4 | An entry fully consumed by stripping is a counted skip `SkipKind::StrippedAway`; no strict mode | No new config flag |
| Q5 | `./` and a root or drive prefix do not count as components | The rewrite runs on the normalized component list; the differential corpus records any bsdtar or GNU difference |
| Q6 | A hardlink to an unselected or stripped target is refused with a typed error naming link and target | No closure of the selection |
| Q7 | `Staging::AtomicReplace` with a non-default selection or strip is refused in core as `InvalidConfiguration{EntrySelection, NotSupported}` | The CLI and bindings inherit the refusal; they add no check |
| Q8 | `PathRewrite::Flatten` is in this PR, implemented last in the track | Task order, section 9 |
| Q9 | Symlink and hardlink entries under `Flatten` are refused with a typed error | No silent loss |
| Q10 | Collisions after strip or flatten follow `ExistingFiles` (see FR-020 in the spec): `Skip` first wins and counts a duplicate, `Overwrite` replaces where kinds allow, `Refuse` refuses an occupant the run did not create | No new default |
| Q11 | Patterns are case-sensitive on every host, as the create matcher | One shared matcher |
| Q12 | `ArchiveManifest` stores the `EntrySelection` it was listed with; `ArchiveManifest::dispositions(&SecurityConfig)` (limits and policies only; the selection comes from the manifest) yields `(entry, Disposition::{Extract(LandingPath), Skip(SkipKind)})`; `landings(config)` projects through the stored selection; `total_size()` keeps counting every entry | A manifest cannot disagree with the selection of its own listing |
| Q13 | `verify --check-integrity` decodes and checks unselected entries too | The gate speaks for the whole archive |
| Q14 | CLI: `--include`, `--exclude`, `--strip-components` only; no positional members, no `-C` | |
| Q15 | A selection skip is charged to `max_file_count` exactly as an allowlist skip is; the track reads the current extract, list and verify behavior first and aligns all three | Task T-005 |
| Q16 | No filter callback, in core or in the bindings | |

> [!warning] Spec amendment
> FR-020 and the edge-case row for `a/x` and `b/x` named `skip_duplicates`. W0 replaced that bool and `DuplicatePolicy` with `ExistingFiles {Skip, Overwrite, Refuse}`; the spec text is corrected to match. See section 5.

## 2. Architecture

### 2.1 Types (module `selection`, crate-private module, root re-exports)

All new public items are re-exported at the crate root. After #978B the modules are private, so the root `pub use` is the only path.

| Type | Pattern | Purpose |
|------|---------|---------|
| `EntrySelection` | immutable value, builder-only construction | Holds `include: Box<[EntryPattern]>`, `exclude: Box<[EntryPattern]>`, `rewrite: PathRewrite`. Default selects all and keeps paths. Fields private; `selects(&NormalizedPath) -> Selected` |
| `EntryPattern` | the shared pattern type (module `pattern.rs`; renamed from the creation `ExcludePattern` in #1041, refusal type `PatternRefusal`) | One grammar (`Exact`, `Prefix`, `Suffix`, `Path`; superseded by the glob grammar of [[023-entry-selection-glob-patterns/spec]]), one `TryFrom<&str>`, one `Display`. The type lives in a shared module and create uses it too, so the grammar has one definition (DRY, FR-004) |
| `PathRewrite` | closed `#[non_exhaustive]` enum | `Keep` (default), `Strip(StripComponents)`, `Flatten`. One enum, so strip and flatten cannot combine (FR-060) |
| `StripComponents` | newtype over `NonZeroUsize` | Range 1 to `max_path_depth` of the construction; one boundary function in `limit.rs` style takes the runtime integer (`i64`) and refuses `0`, negatives and out-of-range as `InvalidConfiguration{StripComponents, ..}` |
| `Selected` | result enum | `Extract(Rewritten)` or `Skip(SkipKind)` where the kind is `NotSelected` or `StrippedAway` |
| `Rewritten` | proof newtype, private constructor | The component list that remains after the rewrite; the only input of the second `SafePath` validation. The rewrite function is its only producer (FR-012, NFR-001) |
| `Disposition<'a>` | enum | `Extract(LandingPath)`, `Skip(SkipKind)` or `Refuse` (an entry validation refuses or that cannot be placed, #1036) for `ArchiveManifest::dispositions(&SecurityConfig)` |
| `SelectionError` | typed error content, no new top-level variant where an existing one fits | Unmatched include patterns (`ArchiveError::UnmatchedInclude{patterns: Box<[EntryPattern]>}`, wrapped in `Partial` like other late errors); hardlink whose target is not extracted (`ArchiveError::HardlinkTargetNotExtracted{link, target}`) |

`ConfigSetting::{EntrySelection, EntryInclude, EntryExclude, StripComponents}` and `SkipKind::{NotSelected, StrippedAway}` already exist from W0 (`73d694b`) and are not redefined. The new `ArchiveError` variants and their `ErrorCode` and `FfiKind` mappings are owned by the track; they follow the W0 error conventions (typed fields, host paths redacted where they are host paths, entry paths rendered as today).

### 2.2 Where the value lives (Q1)

- `SecurityConfig::selection` is a public field in the same style as `allowed_extensions`, with builders `with_include`, `with_exclude`, `with_strip_components`, `with_flatten`, and a whole-value `with_selection(EntrySelection)`.
- Builders are the only way to build the value; the value is immutable after `SecurityConfig` validation.
- `SecurityConfig::for_listing` keeps the selection (it resets write-time flags only), so `ListRequest::for_extraction` and the CLI listing pass see what extraction sees.
- Selection is an operational choice rather than a security limit, but putting it in the config is what makes `list`, `verify`, sinks and `extract` share one value without a signature change. The doc comment says so.

### 2.3 One gate

There is one per-entry decision function, called from the existing per-entry gate that already hosts the extension allowlist (`is_extension_allowed` in `formats/common.rs`, `Tally::record_extension_skip` in `formats/target.rs`, `land` in `inspection/landing.rs`). Handlers do not embed their own copy (NFR-009).

Order, per entry (FR-010):

1. Validate the original path as today (`SafePath`, traversal, banned components, depth, length, reserved names, placement). A refused original path stays refused under any selection (FR-011, NFR-002).
2. `EntrySelection::selects` on the normalized original path, raw component bytes (FR-005, FR-006, FR-007): not selected gives `Skip(NotSelected)`.
3. Rewrite (strip or flatten) on the normalized component list: nothing left gives `Skip(StrippedAway)` (FR-014).
4. `SafePath::validate_in` on the `Rewritten` value, with the same tree, budget and model (FR-012, FR-015, FR-033).
5. Extension allowlist on the remaining regular files (an entry skipped for selection is counted once, under the first reason).
6. Quota.

The same function backs `landing_paths`, `landings`, `dispositions`, `verify` and every sink, so the three operations cannot drift (FR-050, NFR-008).

### 2.4 Shared admission gate with #972

#972 added `ExtensionFilter` to `SecurityConfig` and made its check part of the admission of a regular file. The selection gate is the same function with a wider decision type, not a second one:

- The per-file admission in `formats/common.rs` becomes `admit(entry, config) -> Admission`, with `Admission::{Extract(Rewritten), Skip(SkipKind)}`; `SkipKind::ExtensionNotAllowed` comes from the allowlist arm, the two new kinds from the selection arm.
- `is_extension_allowed` stays the allowlist predicate and is called from `admit` only. `land` in `inspection/landing.rs` calls `admit` too, replacing its direct call.
- The core-selection developer rebases onto the #972 merge before touching `admit`; the type `ExtensionFilter` is not changed by this plan.

### 2.5 Collisions (FR-020 to FR-022)

Collision detection stays in `VirtualTree` (landing projection) and in the host and sink occupancy rules; they now see the rewritten `SafePath`.

| `ExistingFiles` | Collision on one landing after rewriting |
|-----------------|------------------------------------------|
| `Skip` | first entry wins; the later one is a counted `Duplicate` skip |
| `Overwrite` | a later file replaces an earlier one where kinds allow; kind conflicts stay refused under every variant |
| `Refuse` | an occupant created by this run is skipped as a duplicate (the run record); any other occupant is `DestinationOccupied` |

The existing refusals (file over directory, symlink over file or link, hardlink over anything) are unchanged. Case folding follows the destination `PathModel` (FR-021). Flatten collisions are reported as `Duplicate`, as for strip; the spec's FR-061 question is closed by Q10 (no new kind).

### 2.6 Links (FR-030 to FR-033)

- A symlink is validated at its rewritten landing with its original, unrewritten target text. `top/link -> ../other/x` with strip 1 is `SymlinkEscape`.
- A hardlink target is an archive path: it goes through `route_entry_in` as well and the mapped target is validated as a `SafePath`. If the target is not selected, is stripped away, or is skipped for another reason, the link is refused with `HardlinkTargetNotExtracted{link, target}` (Q6).
- The hardlink mapping lives in the `sink.rs` and `target.rs` hardlink regions, where core-selection owns the gate and hardlink-mapping regions (see section 7).
- Under `Flatten`, a symlink or hardlink entry is refused with a typed error (Q9). The error names the entry; no skip.

### 2.7 Quotas and skips (FR-040 to FR-045)

- A selection skip creates no directory, charges neither `max_total_size` nor `max_file_size`, and is charged to `max_file_count` as an allowlist skip is (Q15). Task T-005 reads the current extract, list and verify behavior before changing a line: since #1038 extract, `list` and `verify` all count every entry (directories, links and skipped entries included) once.
- Compressed TAR: skipped data goes through the existing ratio-bounded skip drain; scope `SkippedEntries` (FR-042). No new decode path.
- Unmatched include (Q3): the run keeps a bit set over the include patterns, `include.len()` bits, set when a pattern matches any scanned entry (selected or excluded). At the end of a successful scan, a pattern with no bit raises `UnmatchedInclude` carrying `Partial`; `list` raises it in `ListMode::Strict` only and `verify` reports it (#1033). Exclude patterns that match nothing are not an error (FR-044).
- Progress: skipped entries are reported as skipped (FR-045).

### 2.8 `list`, `verify`, manifest (Q12, Q13)

- `ArchiveManifest` gains a private `selection: EntrySelection` captured at list time (`ListRequest` passes the config's selection when it builds the manifest; `ArchiveManifest::new` takes the default).
- `dispositions()` yields every entry with its `Disposition`. `landing_paths` and `landings` project through the stored selection and omit skipped entries. The `config` parameter keeps supplying only what it supplies today (limits, features, extension filter).
- `total_size()` counts all entries, including unselected ones (Q12), so size gates stay conservative.
- `verify` runs the same gate, reports every refusal extraction would raise (FR-052), validates original paths of unselected entries (FR-054), and with `--check-integrity` decodes unselected entries too (Q13).

### 2.9 Staging (Q7)

- `Staging::Atomic`: selection and rewrite apply inside the staging directory; an unmatched include raises `Partial`, rolls back and publishes nothing (FR-103). The effective occupant policy inside staging is `Refuse` (W0 design), so a planted file at a landing cannot survive.
- `Staging::AtomicReplace` with `selection != EntrySelection::default()`: refused in core before the archive is opened, as `InvalidConfiguration{EntrySelection, NotSupported}`. The check sits in `api.rs::extract_staged` next to the existing `Staging` match. The reason is that the swap would delete everything in the destination that the subset does not contain.
- `Staging::InPlace`: no restriction.

### 2.10 Surfaces

| Surface | Change |
|---------|--------|
| CLI | `--include <PATTERN>` and `--exclude <PATTERN>` (repeatable), `--strip-components <N>` on `extract`, `list`, `verify`; `--flatten` is a CLI flag and conflicts with `--strip-components` in clap. Parsed once into the typed values; refusal exits 1 with the JSON envelope naming the setting. `--json` `skipped_by_kind` shows the new kinds; `list` and `verify` JSON carry the disposition. The CLI maps `AtomicReplace` refusal from core unchanged |
| Python | `extract_archive*` takes `strip_components: int | None`, `include: Sequence[str] | None`, `exclude: Sequence[str] | None`, `flatten: bool` (documented as mutually exclusive with `strip_components`; a `bool` is acceptable at the boundary, mapped to `PathRewrite` once). Empty `include` and `exclude` lists mean "no patterns" and are not refused, because an empty list there is not fail-open (consistent with #991 `banned_components` and `exclude_patterns`). `.pyi` updated |
| Node | `extractArchive*` options object: `stripComponents`, `include`, `exclude`, `flatten`; same rules. `index.d.ts` regenerated |
| Bindings | Map types and parse through the core boundary functions only; errors come from `ArchiveError::into_ffi_message()` (FR-104, NFR-003) |

## 3. Security considerations

- The only constructor of a post-rewrite landing is `Rewritten` into `SafePath::validate_in`, so "validated name, then stripped" is unrepresentable (NFR-001). No format handler, sink or host receives a rewritten string.
- A refused original path is refused before selection runs, so selection cannot turn a refusal into an acceptance (NFR-002).
- Symlink target text is never rewritten (FR-030). Hardlinks to non-extracted targets are refused, never copied (FR-032).
- `Staging::AtomicReplace` with a subset is refused so the swap cannot delete unrelated destination content.
- Selection patterns compare raw bytes; no UTF-8 decoding step can disagree with the validator.
- `rust-security-maintenance` runs after every change, and the live-test critical paths (traversal, symlink and hardlink validation, quota and ratio, `--atomic`) run under strip and selection before the PR.

## 4. Testing strategy

| Layer | Content |
|-------|---------|
| Unit | `EntryPattern` shares the create grammar tests; `StripComponents` boundary (0, negative, above depth); normalization (`./`, `\`, drive prefix, root); `selects` truth table (include, exclude, exclude wins, `Path` subtree) |
| Integration, per format | TAR (all codecs), ZIP, 7z x `HostTarget`, `MemorySink`, custom `EntrySink`: wrapper unwrap, `top/` stripped, N-or-fewer components, `a/x` and `b/x` collision under `Skip`, `Overwrite`, `Refuse`, symlink escape under strip, hardlink target unselected or stripped, unmatched include, `--atomic` rollback, `AtomicReplace` refusal |
| Parity (SC-003) | For every fixture and selection: landings equal `landing_paths`, every extract refusal is a verify issue |
| Quota (SC-004) | Mirrors of #831 and #846 for the new kinds |
| Decode bound (SC-005) | `.tar.gz` of zeros with one included file gives `ZipBomb{SkippedEntries}` |
| Regression (SC-006) | Every existing traversal, symlink and hardlink fixture re-run under strip 1 and an include never accepts what the plain run refuses |
| Differential (SC-001, SC-002) | bsdtar, GNU tar, cpython `tarfile`, node-tar on a crafted corpus; deliberate differences are listed in the track handoff |
| Fuzz (SC-007) | Extraction fuzz target gains a selection and strip input |
| Bindings (SC-009) | Same selection gives the same set and the same typed error in CLI, Python and Node |
| Bench (NFR-006) | Default path within 10% of the baseline in `.local/testing/benchmarks.md`; unselected path within 10% of the allowlist skip |

## 5. Spec updates in the same batch

- `spec.md`: FR-020 and the matching edge-case row use `ExistingFiles` instead of `skip_duplicates`; the Out of Scope line about an overwrite-policy enum is replaced (the enum exists now); section 9 records Q1-Q16 as resolved; status moves from research draft to planned.
- Other specs touched by this batch are listed in the batch handoff (`ExistingFiles`, `Staging`, `Cancelled`, `ReadFaults`, typed zip header findings, #978B, binding `existing_files`).

## 6. Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| A format handler keeps its own strip or match | Review gate: a grep for `strip_prefix`/`components().skip` in `formats/` outside the gate fails review; one function serves all |
| `ArchiveManifest` captured selection diverges from the config passed to `landings` | `landings` ignores the config's selection and reads the stored one (Q12 amendment M4); test for a config with a different selection |
| Flatten collision data loss | `ExistingFiles::Refuse` is available, and the CLI documents it in `--flatten` help; the default stays `Skip` (Q10) |
| Merge conflicts in `sink.rs` and `target.rs` | Region ownership, section 7; rebase onto the PR branch before handing to the lead |
| Differential corpus shows a bsdtar and GNU disagreement on `./` | Q5 default stands, the difference is recorded, not silently chosen |
| `max_file_count` charge differs between operations today | T-005 aligns all three before adding selection |

## 7. Ownership and merge regions

Track `core-selection` branches from the post-W0 tip of `feat/981-exarch-v-panics-with-exit-101` and rebases onto the current PR branch before handoff. It merges after core-staging.

| File | Region owner |
|------|--------------|
| new `selection` module, `config.rs` selection field, `inspection/{landing,manifest,list,verify}.rs`, `request.rs` | core-selection |
| `formats/common.rs` admission gate (`admit`, `is_extension_allowed`) | core-selection |
| `formats/target.rs` (except the occupant arm) and `sink.rs` gate and hardlink-mapping regions | core-selection |
| `formats/target.rs` occupant arm, `sink.rs` occupant matches, `common.rs` occupant sites | core-staging |
| `sink.rs` copy region, `common.rs` copy lines, `sevenz/write.rs` | core-errors |

## 8. Constitution check

| Principle | Status |
|-----------|--------|
| Typed validation pipeline | Pass: `Rewritten` proof type feeds `SafePath` |
| Bindings map types only | Pass: parse through core boundary functions |
| Illegal states unrepresentable | Pass: `StripComponents` non-zero, one rewrite enum, immutable selection |
| Performance (VI) | Gate in section 4; default path unchanged |
| No backward-compat work before 1.0 | Pass: `skip_duplicates` replacement and new config field are breaking and go in the CHANGELOG |

## 9. Implementation order

See [[tasks]] for the task list. Flatten (T-012 to T-014) is implemented last in the track, after strip and selection pass the full gate, so it can be reviewed or reverted as one unit.

## 10. As-built reconciliation

The names in sections 2.1 to 2.4 are the plan's. What shipped differs as follows; the spec's section 11 repeats the behavioral differences.

| Plan | As built |
|------|----------|
| `admit(entry, config) -> Admission::{Extract, Skip}` | `ValidatorCore::route_entry_in` validates the original `SafePath`, runs `EntrySelection::decide`, and revalidates a rewritten name through `SafePath::validate_rewritten_in(&Rewritten)`; `route_validated` is the same step for `land` and `verify`. `FileAdmission` became `Admission {Admit, Skipped}`, `FileScreen` became `Gated<T> {Admit, Skip(SkipKind)}`; `ExtractTarget::validate_{directory,symlink,hardlink}` take `&mut Tally` and return `Admission`; `ExtractTarget::finish_scan` runs the unmatched-include check |
| Builders `with_include`, `with_exclude`, `with_strip_components`, `with_flatten` | `SecurityConfig::with_selection`, `try_add_include(&str)`, `try_add_exclude(&str)` and `with_path_rewrite(PathRewrite)`; `EntrySelection` has `with_include`, `with_exclude`, `with_rewrite`, `is_default`, `include()`, `exclude()`, `rewrite()` |
| `StripComponents` from `i64` | `StripComponents::new(NonZeroU64, max_path_depth: NonZeroUsize)`; bindings parse with `positive_from_i128` or `positive_from_f64` under `ConfigSetting::StripComponents` and then call `new`; `EntryPattern::parse_for(ConfigSetting, &str)` is the shared pattern boundary and `EntryPattern` is an alias of `EntryPattern` |
| `SelectionError` and `HardlinkTargetNotExtracted` as `ArchiveError` | `ArchiveError::UnmatchedInclude { patterns }` is top-level; `HardlinkTargetNotExtracted { link, target }` and `LinkUnderFlatten { kind, name }` are `Violation` variants (sub-codes `LinkTarget`, `LinkPolicy`); no `ConfigProblem` was added |
| `dispositions()` without config | `dispositions(&SecurityConfig)` |
| Disposition discriminant in the bindings | Core `DispositionKind` (`extract`, `skip`, `refuse`) with `Disposition::kind()`; Python and Node expose it as `action` and the skip reason as `kind`; Python computes the list once at listing time and keeps it as an attribute (#1009, #1010) |
| Selection helpers in the bindings | `EntrySelection::with_strip`, `with_flatten`, `with_include_list`, `with_exclude_list` (#998); an absolute hardlink target is mapped with the entry names where absolute paths are allowed (#997) |
| Unmatched include bit set per run | As planned, evaluated in `finish_scan` before the hardlink pass, also on empty archives |
| Python `flatten: bool` and `include`/`exclude` keyword arguments on extract | Selection on `SecurityConfig` for Python and Node (spec FR-104) |
| CLI `--flatten` | As planned; conflicts with `--strip-components` at the clap level |
| T-005 audit | Extraction charges no allowlist skip, `list` charged the count alone, `verify` charged the full size; `verify` was aligned to the count alone |
| `ListedArchive` size | `SecurityConfig` grew by one 48-byte `EntrySelection` (boxed slices); `ExtractPlan::Listed` boxes the listing for the clippy large-variant lint |

Verification as built: 40 integration tests over TAR, ZIP and 7z for host and `MemorySink`, a bsdtar differential test, the extraction fuzz target with a selector-derived selection, and a `skipped_entries` bench (allowlist skip 10.762 ms against exclude-pattern skip 10.755 ms on 10k files, within noise).
