---
tags:
  - sdd
  - delta
created: 2026-11-15
status: open
related:
  - "[[003-config-api/spec]]"
---

# Delta: config surface of the #1230 batch

## ADDED

### FR-073

`SecurityConfig` SHALL expose `repeated_paths: RepeatedPaths` (`KeepFirst` default, `Refuse`; `#[non_exhaustive]`, builder `with_repeated_paths`) as specified in [[030-duplicate-entry-repeated-paths/spec]] (#1201).

### FR-074

`SecurityConfig` SHALL expose `max_kdf_work` (`NonZeroU64`, default 2^27), and the request types SHALL take an optional `Password` per request, never stored in `SecurityConfig`, as specified in [[024-encrypted-archive-support/spec]] FR-001 and FR-032 (#1023). Both sit behind the core `encryption` feature where they depend on it.

### FR-075

`CreationConfig` SHALL expose `parallelism: Parallelism` (`Sequential` default, `Threads(NonZeroUsize)`; `#[non_exhaustive]`, builder `with_parallelism`) as specified in [[027-zip-parallel-compression/spec]] (#1027).
