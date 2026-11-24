---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: open
related:
  - "[[003-config-api/spec]]"
  - "[[002-format-handlers/changes/tar-sparse-expand]]"
---

# Delta: TarSparsePolicy on SecurityConfig (#1349)

> [!info] Scope
> Requirement id continues the table of [[003-config-api/spec]] (last id FR-075; the open delta `atomic-extract-owner-restricting-umask` adds FR-076). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084 (delta `tar-sparse-expand`). Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-077

THE SYSTEM SHALL expose `SecurityConfig::tar_sparse: TarSparsePolicy` and the builder `with_tar_sparse(TarSparsePolicy)` ([[002-format-handlers/spec]] FR-081). The default and `SecurityConfig::permissive()` are `TarSparsePolicy::Refuse`; the value is immutable after construction like the rest of `SecurityConfig`. The extract, list, verify and sink requests honour it, so a `verify` or `list` of an archive and its extraction judge a sparse entry the same way. New public items: `TarSparsePolicy` (`#[non_exhaustive]`), `ConfigSetting::TarSparse`, `TarAmbiguity::SparseMap { defect }`, `SparseMapDefect`, and `TarHeaderField::{SparseOffset, SparseLength, RealSize}`.

**Priority**: must
