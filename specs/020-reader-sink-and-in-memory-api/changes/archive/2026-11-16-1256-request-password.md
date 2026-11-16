---
tags:
  - sdd
  - delta
created: 2026-11-16
status: merged
related:
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Delta: Optional password on every request and on the bytes list and verify (#1256)

## MODIFIED

### FR-109

Old: `MemoryExtractRequest` carries an optional password.
New: every request type takes `with_password(Option<Arc<Password>>)` (`None` is no password; `Password::shared` builds the handle), and the Python and Node `list` and `verify` bytes functions take `password` as their last parameter.
