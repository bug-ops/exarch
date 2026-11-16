---
tags:
  - sdd
  - delta
created: 2026-11-16
status: merged
related:
  - "[[007-node-bindings/spec]]"
---

# Delta: Password on the in-memory list and verify functions (#1256)

## MODIFIED

### FR-133

The in-memory list and verify functions (all progress variants) take `password` as their last parameter, validated before the archive is read.
