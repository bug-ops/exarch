---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: open
related:
  - "[[006-python-bindings/spec]]"
  - "[[002-format-handlers/changes/tar-sparse-expand]]"
---

# Delta: Python `tar_sparse` setting (#1349)

> [!info] Scope
> Requirement id continues the table of [[006-python-bindings/spec]] (last id FR-124). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084. Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-125

`SecurityConfig` SHALL expose the `tar_sparse` property (string `"refuse"` or `"expand"`, default `"refuse"`; any other value raises `ValueError`) and `with_tar_sparse(policy)`, typed in `exarch.pyi` and mapped to `SecurityConfig::with_tar_sparse` ([[002-format-handlers/spec]] FR-081). The binding does type mapping only.

**Priority**: must
