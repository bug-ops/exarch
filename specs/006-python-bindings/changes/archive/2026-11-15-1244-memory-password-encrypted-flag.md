---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[006-python-bindings/spec]]"
---

# Delta: Python surface of the #1237 to #1246 batch

## MODIFIED

### FR-123

`extract_archive_to_memory[_with_progress]` and `extract_archive_to_callback` take `password`; `ArchiveEntry.encrypted` is a `bool`; `unusable_password` is a `reason` (#1241, #1242, #1246).
