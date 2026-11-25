---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: merged
related:
  - "[[019-verify-and-list-model/spec]]"
  - "[[002-format-handlers/changes/archive/2026-11-25-tar-sparse-expand]]"
---

# Delta: verify and list of sparse TAR entries (#1349)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1349, #1372).

> [!info] Scope
> Requirement id continues the table of [[019-verify-and-list-model/spec]] (last id FR-067). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084. Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-068

WHEN `TarSparsePolicy::Expand` is set and `list` or `verify` meets an `S` entry, THE SYSTEM SHALL NOT read it through the hole-expanding reader: the integrity pass records the entry as `DecodeOutcome::Verified` without reading it, and its archived bytes are consumed by the skip of the next entry ([[002-format-handlers/spec]] FR-084), which decodes the compressed stream. A truncated or corrupt stream, or a ratio trip, fails the operation there (`InvalidArchive` / `ZipBomb`) and no report is produced. This is the guarantee a regular TAR entry has (TAR carries no per-entry checksum: integrity means the bytes decode and are all present). The cost of `list` and `verify` is the archived size; only a writing extraction costs the real size.

**Priority**: must
