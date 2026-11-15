---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[001-exarch-system/spec]]"
---

# Delta: in-package testkit for exarch-core tests (#1237)

## ADDED

### NFR-013

The `exarch-core` tests use an in-package testkit under `crates/exarch-core/src/testkit`, so the packaged crate names no `exarch_testkit` and its tests compile and pass when unpacked; `exarch-testkit` stays an unpublished facade over the same files for the CLI.
