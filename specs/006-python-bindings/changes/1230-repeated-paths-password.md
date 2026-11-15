---
tags:
  - sdd
  - delta
created: 2026-11-15
status: open
related:
  - "[[006-python-bindings/spec]]"
---

# Delta: Python surface of the #1230 batch

## ADDED

### FR-122

`SecurityConfig.with_repeated_paths(str)` SHALL accept `"keep_first"` and `"refuse"` (closed-enum snake_case strings), expose the matching attribute and a `.pyi` entry, and raise the typed repeated-path error (#1201).

### FR-123

The extract, list and verify functions SHALL take `password: bytearray | None`; `bytes` and `str` are refused with a typed error; `SecurityConfig` SHALL expose `max_kdf_work`. Core owns every check (#1023, [[024-encrypted-archive-support/spec]] FR-003).

### FR-124

An entry below an existing escaping symlink SHALL raise `SymlinkEscapeError` in every format; the test in `test_destination_errors.py` asserts that kind only (#1230).

Parallelism stays unexposed in the Python binding (#1027).
