---
tags:
  - sdd
  - delta
created: 2026-11-16
status: merged
related:
  - "[[006-python-bindings/spec]]"
---

# Delta: Password on the in-memory list and verify functions (#1256)

## MODIFIED

### FR-123

The in-memory list and verify functions (all progress variants) take `password` as their last parameter, validated before the archive is read.
