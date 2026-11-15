---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Delta: Password on the in-memory and callback API (#1241)

## ADDED

### FR-109

`MemoryExtractRequest` carries an optional password; `extract_reader_to_memory` and `extract_reader_to_callback` apply it, and the Python and Node memory and callback functions take it as their last parameter.
