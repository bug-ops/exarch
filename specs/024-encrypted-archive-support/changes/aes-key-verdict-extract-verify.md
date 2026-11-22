---
tags:
  - sdd
  - delta
  - formats/sevenz
  - encryption
created: 2026-11-22
status: open
related:
  - "[[024-encrypted-archive-support/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[019-verify-and-list-model/spec]]"
---

# Delta: extract and verify share the AES key-verdict rule (#1289)

> [!info] Scope
> Requirement ids continue the table of [[024-encrypted-archive-support/spec]] (last id FR-042). FR-010, FR-014 and FR-020 are read together with FR-043.

## ADDED

### FR-043

WHEN a 7z block with an AES coder fails to decode and the failure is not an I/O error, THE SYSTEM SHALL report `Violation::Encrypted { reason: WrongPasswordOrCorrupt }` in `extract` and in `verify` alike, by one rule: the decoder errors that map to a key verdict (checksum mismatch, and any other non-I/O decoder error of that block) are that refusal for an AES block. In particular an AES-wrapped PPMd block whose range decoder cannot start under a wrong password is `wrong_password_or_corrupt` in `extract`, as `verify` already reported it. Rules:

- An I/O error keeps its read classification (FR-063): `Io` for a source or destination fault, never a key verdict.
- The rule applies to AES blocks only: a plain block keeps its own error kind and text (`InvalidArchive`), including in a non-solid archive that mixes AES and plain blocks (FR-010).
- The rule is error-only: it changes no admission decision, no quota charge and no successful extraction.
- Every non-I/O decoder error of an AES block counts, including an error caused by key-independent coder properties (a PPMd parameter or memory error), because `verify` already maps it to a key verdict; the two commands must not disagree.
- A declared-size overrun and a coder that admission refuses (FR-073) keep their own reports, as FR-014 states; they are not decoder errors of this rule.
- The classification is typed, never by message text, and one test asserts that the AES-block predicate and the `verify` classification agree for every decoder error shape.

**Priority**: must

### Edge cases (section 6 rows)

| Scenario | Expected Behavior |
|----------|-------------------|
| AES-wrapped PPMd 7z block, wrong password that fails at the range decoder | `WrongPasswordOrCorrupt` from `extract` and from `verify` (FR-043, #1289); before this change `extract` reported `InvalidArchive` |
| Plain PPMd 7z block with corrupt data | `InvalidArchive`, text unchanged (FR-043) |

## MODIFIED

(none)

## REMOVED

(none)

## Deviations

(none)
