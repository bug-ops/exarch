---
tags:
  - sdd
  - delta
created: 2026-11-15
status: open
related:
  - "[[021-create-staging-and-output-policy/spec]]"
---

# Delta: parallel ZIP creation (#1027)

## ADDED

### FR-054

WHEN `CreationConfig` sets `Parallelism::Threads(n)` THE SYSTEM SHALL prepare ZIP entries concurrently under the rules of [[027-zip-parallel-compression/spec]]: sources opened and verified on the main thread in walk order (FR-048, FR-049), workers never re-open by path, exact-length copy and `SourceChanged` unchanged (FR-051, FR-052), output through the staged path of FR-005 unchanged, and output bytes equal to `Sequential`. A regular file of at most 8 MiB takes the prepared-entry path in both modes, so the sequential bytes change once relative to 0.10.
