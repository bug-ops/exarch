---
tags:
  - sdd
  - delta
created: 2026-11-16
status: merged
related:
  - "[[024-encrypted-archive-support/spec]]"
---

# Delta: Encrypted ZIP selection, 7z verify classification and header limits (#1261, #1248, #1262, #1256, #1264)

## ADDED

### FR-035

An encrypted 7z header is bounded like a plain one: its declared unpack sizes and raw record are checked against the per-entry size cap before parsing, then parsed under `max_decoder_memory`; exceeding a limit is a quota refusal, never a wrong password (#1262).

## MODIFIED

### FR-001

Old: `with_password` on the request types.
New: `with_password(Option<Arc<Password>>)` on the extract, list, verify, sink-extract and memory-extract requests; `Password::shared` builds the shared handle.

### FR-002

New sentence: a `--password-fd` descriptor that is open but not readable is reported as such (#1264).

### FR-003

New sentence: the in-memory `list` and `verify` functions of both bindings take the password as their last parameter (#1256).

### FR-014

New sentence: a wrong password on an AES 7z block makes `verify` report a per-entry `ENCRYPTED` / `wrong_password_or_corrupt` issue, mark the rest of the block not verified and continue with later blocks (#1248).

### FR-015

New text: an `extract` whose selection extracts no encrypted ZIP entry demands no password; unselected encrypted entries go through a name-only sealed route and their payload is never read; standalone `list` and `verify` are unchanged; ZipCrypto stays `WeakEncryptionRefused` (#1261).

## Deviations

- FR-014: verify continues past the failing block instead of stopping at it.
- FR-015: the unselected set holds every encrypted entry the selection does not certainly extract, for parity with the plain twin's path errors.
