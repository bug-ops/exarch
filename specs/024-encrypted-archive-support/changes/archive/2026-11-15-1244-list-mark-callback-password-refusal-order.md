---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[024-encrypted-archive-support/spec]]"
---

# Delta: Encryption refinements of the #1237 to #1246 batch

## MODIFIED

### US-006, FR-014

Old: `list` lists an encrypted ZIP with no encrypted mark; a 7z with AES content under a plain header and no password stays FAIL in `verify` (reason `not_decodable`, `ENCRYPTED` issue).

New: `list` marks encrypted entries (core `EntryEncryption { Plain, Encrypted }`; boolean `encrypted` in CLI JSON, Python and Node; `(encrypted)` in `list -l`), and the 7z case is an unverified `encrypted` WARNING in `verify` only; `extract` still fails with `password_required` (#1242, #1243).

### FR-004, FR-020

Old: a non-UTF-8 7z password is reported as `WrongPasswordOrCorrupt`.

New: it is refused as `UnusablePassword` (token `unusable_password`) on every surface; one order applies on the header and the content path: `password_required`, `unusable_password`, `weak_encryption_refused`, `kdf_cost_exceeded` (#1246).

### FR-016

Old: the in-memory and callback entry points take no password.

New: `MemoryExtractRequest`, `SinkExtractRequest::with_password`, and the Python and Node memory and callback functions take one (#1241).

### FR-031

Old: no raw-key check for an encrypted header.

New: when the probe models the header, any AES coder with power `0x3F` is refused as `weak_encryption_refused` before `Archive::read` (#1239).

## ADDED

### FR-010 (7z block classification)

A decode failure is classified by the block that raised it, so a plain block of a mixed non-solid 7z keeps the plain error kind (#1240).

## REMOVED

### Deviations

The rows for US-006 and FR-014, FR-004 and FR-016 are removed from section 9; they are resolved.
