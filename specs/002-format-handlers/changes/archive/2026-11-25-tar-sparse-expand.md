---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: merged
related:
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[019-verify-and-list-model/spec]]"
---

# Delta: opt-in expansion of old GNU sparse TAR entries (#1349)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1349, #1372). The CLI requirement is FR-152 in `005-cli/spec.md`, not FR-150, which that spec already used.

> [!info] Scope
> Requirement ids continue the table of [[002-format-handlers/spec]] (last id FR-077; the open delta `sevenz-mode-tar-volume-label-pax-mtime` adds FR-078 to FR-080). The surface requirements live in sibling deltas: [[003-config-api/spec]] (FR-077), [[005-cli/spec]] (FR-150), [[006-python-bindings/spec]] (FR-125), [[007-node-bindings/spec]] (FR-136), [[019-verify-and-list-model/spec]] (FR-068). Spec sync applies all of them in the same PR.

> [!danger] Not implemented
> #1301 (blank-size volume label) stays as FR-079 states: tar-rs#499 is open. PAX sparse forms (`GNU.sparse.*`, `SCHILY.realsize`, `SUN.holesdata`) stay refused under both policies; supporting them is a follow-up (enhancement, P4).

## ADDED

### FR-081

THE SYSTEM SHALL provide `TarSparsePolicy { Refuse, Expand }` (`#[non_exhaustive]`, `as_str()` gives `refuse` and `expand`) as the TAR sparse setting of `SecurityConfig`:

- `Refuse` is the default and the value in `SecurityConfig::permissive()`. Under `Refuse`, a GNU sparse entry is refused exactly as FR-051 states ("a GNU sparse entry"); nothing changes.
- `Expand` admits an old GNU sparse entry (typeflag `S`) and extracts it as a regular file with its holes filled with zero bytes. It is the only way a sparse entry is ever extracted.
- Only the old GNU format with typeflag `S` is covered. Every PAX sparse form, in either policy, stays refused (FR-051, FR-075).

**Priority**: must

### FR-082

WHEN the policy is `Expand`, THE SYSTEM SHALL admit an `S` entry only if its sparse map is canonical, and otherwise refuse it with `TarAmbiguity::SparseMap { defect }` (`InvalidArchive`, sub-code `TAR_AMBIGUITY`) naming one `SparseMapDefect`:

| `SparseMapDefect` | Refused construct |
|-------------------|-------------------|
| `PartialSlot` | A map slot with only one of its two fields set |
| `SlotAfterEnd` | A used slot after an unused one |
| `ExtendedFlag` | An extended flag that is neither 0 nor 1 |
| `ExtensionChain` | An extension-block chain that does not match the extended flags |
| `ZeroOffsetExtension` | A used slot in an extension block with a zero offset |
| `InteriorZeroLength` | A zero-length slot that is not the last one |

- The offset, length and real-size fields (`TarHeaderField::{SparseOffset, SparseLength, RealSize}`) SHALL be canonical octal or base-256 numbers under the same rule as the other numeric fields (FR-051); a non-canonical one is the existing `NonCanonicalNumber` refusal naming that field.
- A PAX `size` record on an `S` entry is refused (`UnsupportedRecord`).
- The extension window accepts `k` extension blocks when the entry's header position plus `512 * k` equals the window end; any other length is the existing window-mismatch refusal.
- The header check runs before the entry is classified, so an `S` entry never reaches extraction as a file without having passed it.

**Priority**: must

### FR-083

WHEN an `S` entry under `Expand` is extracted, THE SYSTEM SHALL charge its real (expanded) size, not its archived size, against `max_file_size` and `max_total_size` through `QuotaTracker`, before any byte is written, and SHALL fill the holes with zeros while writing. Rules:

- Real size over a limit is refused as the usual quota refusal; the entry is not partially written because of the pre-charge.
- NO compression-ratio check applies to the synthesised hole bytes (the ratio is defined on archived input, and holes carry none). The quotas are the only bound; this is documented. Setting both limits to `Limit::Unbounded` leaves no ceiling on the expanded size, and this is documented too.
- The copy loop honours cancellation like any other entry.

**Priority**: must

### FR-084

WHEN an `S` entry under `Expand` is not read (skipped by the extension allowlist, by entry selection, by a quota skip, or as an unread entry during `list` or `verify`), THE SYSTEM SHALL skip it by its archived size and SHALL NOT generate hole bytes (`SkipPlan::TarSkip`):

- The bytes consumed this way are exempt from the metadata window and the synthetic-byte counters only. Skipped-entry metering stays on: they are still charged to `meter_skipped`, so `ZipBomb { scope: SkippedEntries }` still bounds a skipped payload.
- A skip reads at most the remaining exempt byte count, so no header byte can pass through the exemption; an exemption left over after the skip is `WindowMismatch`; a failed skip names the sparse entry's path.
- The cost of `list`, `verify` and skips is the archived size; the cost of a writing extraction is the real size.

**Priority**: must

### Edge cases (section 6 rows)

| Scenario | Expected Behavior |
|----------|-------------------|
| Old GNU sparse entry, default config | Refused as in FR-051 (FR-081) |
| Old GNU sparse entry, `Expand`, canonical map | Extracted as a regular file of the real size with zero-filled holes (FR-081, FR-083) |
| `Expand`, map with a partial slot, slot after the end, bad extended flag, broken extension chain, zero offset in an extension block, or interior zero length | `TarAmbiguity::SparseMap { defect }` with the matching defect (FR-082) |
| `Expand`, non-canonical offset, length or real-size number | `NonCanonicalNumber` naming `SparseOffset`, `SparseLength` or `RealSize` (FR-082) |
| `Expand`, PAX `size` record on an `S` entry | `UnsupportedRecord` (FR-082) |
| `Expand`, real size above `max_file_size` or the running total above `max_total_size` | Quota refusal before writing (FR-083) |
| `Expand`, sparse entry with a hole far larger than the archive, not extracted (`list`, `verify`, allowlist skip) | Cost proportional to archived size; `verify` reports it `Verified`; a bomb in the archived stream still gives `ZipBomb { SkippedEntries }` (FR-084) |
| `Expand`, truncated archive cut inside an `S` payload, `verify` | `InvalidArchive` (FR-084) |
| PAX sparse forms, either policy | Refused (FR-051, FR-075) |
| Sparse-map extension block without the flag that announces it | The block is read as data by all readers; the error appears at the next header (`InvalidArchive`); it cannot be refused earlier without reading entry data |

## MODIFIED

### FR-051

Old: "... a GNU sparse entry; ..." in the refusal list.

New: "... a GNU sparse entry unless the policy is `Expand` (FR-081; PAX sparse forms stay refused in both policies); ...".

## Deviations

Approved during implementation (critic rounds, accepted by the lead):

| Item | Specified | Implemented |
|------|-----------|-------------|
| `TarEntryGuard::check` | `check(metadata_limit)` | `check(metadata_limit, TarSparsePolicy)` |
| `tar_node` classification | GNU sparse is not a file kind | `GNUSparse` is mapped to a file kind in `tar_node` / `effective_entry_type`; safe because the header check runs first (FR-082) |
| Seekable TAR variant | A seekable-source variant for TAR | None: `ArchiveReader::seekable` covers ZIP and 7z only; TAR is read through `Read`, and the skip path is the same one |
| Extra test expectations | `list` omits an allowlist-skipped sparse entry; an extension block with no flag is refused at its entry | Corrected: `list` keeps skipped entries in the manifest for regular files too (only counts them), so sparse entries behave the same; a flagless extension block is detected at the next header (see the edge-case row) |
