---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[007-node-bindings/spec]]"
---

# Delta: Node surface of the #1237 to #1246 batch

## MODIFIED

### FR-133

`extractArchiveToMemory[WithProgress][Sync]` and `extractArchiveToCallback[Sync]` take `password` as the last parameter; every entry kind interface has a boolean `encrypted`; `unusable_password` is a `reason` (#1241, #1242, #1246).
