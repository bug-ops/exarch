---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[019-verify-and-list-model/spec]]"
---

# Delta: FR-043 under the opt-in Refuse policy (#1201)

## MODIFIED

### FR-043

Old: "The first entry at a path SHALL win, mirroring extraction that skips an existing entry; ..."

New: the first entry at a path still wins under the default `RepeatedPaths::KeepFirst`, with every rule of the old text unchanged. Under `RepeatedPaths::Refuse` ([[030-duplicate-entry-repeated-paths/spec]]) the later entry is refused instead: `list` reports `refuse` with `Violation::RepeatedPath`, `verify` reports an issue derived from the same error, and extraction (host and sink) refuses it, a directory over a directory excepted. Where the list model cannot prove a landing unique (record cap passed, or a non-matching spelling under `VolumeIdentity::LandingPaths`) the disposition is `refuse` with `DestinationOccupied`. Host, sink, `list` and `verify` agree per entry while the host record is unsaturated; past the cap extraction fails closed where `list` may still report `skip` (documented, not claimed equal).

## ADDED

### FR-066

Under `Refuse`, a ZIP exact-name repeat SHALL be reported by `verify` as the same `RepeatedPath` finding whatever `zip_consistency` says; under `KeepFirst` the `DuplicateName` finding is unchanged ([[030-duplicate-entry-repeated-paths/spec]] FR-007).
