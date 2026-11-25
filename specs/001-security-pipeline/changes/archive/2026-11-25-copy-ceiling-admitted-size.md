---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-23
status: merged
related:
  - "[[spec]]"
  - "[[013-quota-permit-capability-token/changes/archive/2026-11-25-copy-ceiling-admitted-size]]"
---

# Delta: the streaming ceiling of FR-014 is typed (#1340)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1340, #1347).

> [!info] Scope
> Capability: `001-security-pipeline`. Behavior of FR-014 is unchanged; only the type that carries the ceiling changes. Requirement FR-012 of [[013-quota-permit-capability-token/spec]] holds the contract.

## ADDED

(none)

## MODIFIED

### `QuotaPermit` entity row

Old: Private `bytes` field; produced by `QuotaTracker::reserve` and `charge`; consumed by value via crate-private `into_bytes(self)`, which yields the write ceiling.

New: Private `bytes` field; produced by `QuotaTracker::reserve` and `charge`; read without spending by crate-private `admitted(&self)` and spent by `into_admitted(self)`, which yields the `AdmittedSize` that is the write ceiling of every extraction copy (`copy_cancellable` takes it; no `Option<u64>`, so no uncapped extraction copy is expressible) (#1340).

## REMOVED

(none) `QuotaPermit::into_bytes` is removed (see the 013 delta).

## Deviations

(none)
