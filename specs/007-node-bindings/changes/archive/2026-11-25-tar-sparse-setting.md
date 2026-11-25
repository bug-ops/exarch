---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: merged
related:
  - "[[007-node-bindings/spec]]"
  - "[[002-format-handlers/changes/archive/2026-11-25-tar-sparse-expand]]"
---

# Delta: Node `tarSparse` setting (#1349)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1349, #1372).

> [!info] Scope
> Requirement id continues the table of [[007-node-bindings/spec]] (last id FR-135). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084. Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-136

`SecurityConfig` SHALL expose `tarSparse` (`TarSparsePolicy`, `'refuse' | 'expand'`, default `'refuse'`) and `withTarSparse(policy)`, typed in `index.d.ts` and mapped to `SecurityConfig::with_tar_sparse` ([[002-format-handlers/spec]] FR-081); the exported enum values equal `TarSparsePolicy::as_str`.

**Priority**: must
