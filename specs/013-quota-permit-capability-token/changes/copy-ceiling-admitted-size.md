---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-23
status: open
related:
  - "[[spec]]"
  - "[[001-security-pipeline/spec]]"
---

# Delta: the extraction copy ceiling is an AdmittedSize, `QuotaPermit::into_bytes` is removed (#1340)

> [!info] Scope
> Capability: `013-quota-permit-capability-token`. Internal (`pub(crate)`) surface only; no public API or observable behavior changes.

## ADDED

### FR-012

THE SYSTEM SHALL cap every extraction copy by an `AdmittedSize`: `copy_cancellable` takes `ceiling: AdmittedSize` instead of `expected_size: Option<u64>`, so an extraction copy can be neither uncapped (`None`) nor capped by a number that did not come from a permit. The callers (`copy_and_finish_file` for TAR, ZIP and 7z, the sink `write_staged`, and the hardlink copy `copy_file_content_with_permit`) pass `QuotaPermit::into_admitted()`. The copy loop with an optional ceiling and an optional progress poll (`copy_polled`) stays crate-private for the verification path, whose cap is a declared size, not a quota, and whose drain is intentionally uncapped (#1340).

**Priority**: must

## MODIFIED

### FR-007 and the `QuotaPermit` entity row

Old: `QuotaPermit` carries the reserved `bytes: Uncompressed` (private; spent by crate-private `into_bytes(self)`, the write ceiling).

New: `QuotaPermit` carries the reserved `bytes: Uncompressed` (private). `into_bytes` is removed. A crate-private `admitted(&self) -> AdmittedSize` reads the reserved size without spending the permit (used for the byte-counter overflow check before the file is created), and `into_admitted(self)` spends it into the `AdmittedSize` that caps the copy and is handed to a sink. `AdmittedSize` is built only by these two methods.

### `AdmittedSize` entity row

Old: `Copy` view of the permit's bytes for `EntrySink::create_file*` (#909); `get()`; built only by `QuotaPermit::into_admitted`.

New: `Copy` view of the permit's bytes for `EntrySink::create_file*` (#909) and the write ceiling of the extraction copy (#1340); `get()`; built only by `QuotaPermit::admitted` and `QuotaPermit::into_admitted`.

## REMOVED

### `QuotaPermit::into_bytes`

Replaced by `admitted` and `into_admitted` (see MODIFIED).

## Deviations

(none) The `QuotaPermit::admitted(&self)` accessor was approved by the lead during implementation.
