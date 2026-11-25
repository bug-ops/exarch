---
tags:
  - sdd
  - delta
  - formats/sevenz
  - encryption
created: 2026-11-25
status: merged
related:
  - "[[024-encrypted-archive-support/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
---

# Delta: per-operation 7z AES keys replace the process-wide key slot and turn (#1351, #1352)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1351, #1352, #1372). FR-040, FR-041 and Q10 follow the delta; GN-3 is removed with the upstream report.

> [!info] Scope
> Requirement ids continue the table of [[024-encrypted-archive-support/spec]] (last id FR-043, from the open delta `aes-key-verdict-extract-verify`). Spec sync applies the ADDED rows, then the MODIFIED rows, then moves this file to `changes/archive/`.
> Internal refactor #1362 (one poisoned-lock helper per crate: `crate::sync::lock_unpoisoned` in `exarch-core`, `utils::lock_unpoisoned` in `exarch-node`) changes no observable behaviour and no requirement; no spec covers it.

> [!warning] Public wording
> #1351 and #1352 are a private-vulnerability class. The rows below state behaviour only; docs, changelog and tests carry no worst-case figures.

## ADDED

### FR-044

THE SYSTEM SHALL derive every 7z AES key itself, once per operation, and hand it to `sevenz-rust2` in raw-key form, so no key, key slot or lock is shared between operations:

- Each operation (`extract`, `list`, `verify`, a sink or callback operation) owns its keys. Nothing derived by one operation is visible to another, including an operation nested inside a callback or sink of the outer one and operations running concurrently with other passwords.
- A key is derived lazily, at most once per distinct (power, salt) pair per operation, when the first block that needs it is decoded. Blocks declaring the same pair share the one derived key; a block that is never decoded costs nothing.
- The `sevenz-rust2` archive view used for decoding carries, in each AES coder, the properties of its derived key in raw-key form (power `0x3F`, the 32 key bytes in the password position); `sevenz-rust2` therefore runs no KDF of its own and its process-wide cache is never consulted. The coders are built from public `sevenz-rust2` API only (donor coders parsed from a synthesised header; no fork and no `[patch]`).
- The process-wide key slot, its mirror, and the AES turn (the process-wide lock that serialised AES set-up) are removed, together with the guarantee they provided: encrypted 7z blocks of unrelated operations decode concurrently.
- The 32 key bytes are zeroized on drop. The `sevenz_rust2::Password` copies inside the view are a library type and are not.

**Priority**: must

### FR-045

WHEN an encrypted 7z header is read, THE SYSTEM SHALL work in this order, so that a header that cannot be opened costs nothing:

1. admission on the probe's mode (a missing password is refused before more of the source is read);
2. prefetch of the header bytes into memory (the caller's `Read`/`Seek` never runs under a lock; FR-035 bounds still apply);
3. verification of the header CRCs (start header and next-header) on the prefetched bytes, before any key derivation;
4. admission on the fetched mode;
5. derivation of the header key;
6. the encrypted header is decoded and patched in place, then parsed.

The header key seeds the (power, salt) pair cache of FR-044: a content block declaring the same pair reuses it and derives nothing.

**Priority**: must

### FR-046

WHEN a 7z block cannot be decoded because of its own refused state (its AES coders declare different (power, salt) pairs, a coder with a raw-key power, a power the budget refuses, unparseable AES properties, or a coder without a faithful raw-key twin), THE SYSTEM SHALL fail that block alone: building the decode view never fails as a whole, the other blocks stay decodable, and `verify` reports the refused block's entries and nothing else. The error kinds are those of the corresponding admission rule (FR-047).

**Priority**: must

### FR-047

THE SYSTEM SHALL apply these refusals for 7z AES, in every command:

- A block whose AES coders declare different (power, salt) pairs is refused as unsupported (`Malformation::SevenZUnsupportedCoder`, `InvalidArchive`). This is a user-approved narrowing (L1) of the earlier behaviour, which decoded such a block.
- An encrypted header with more than one AES coder is refused as unsupported in the same way (L1).
- A header AES coder with power 25 to `0x3E` is refused as `KdfCostExceeded`, before any derivation.
- A header AES coder with power `0x3F` (raw key) is refused as `WeakEncryptionRefused`, as FR-031 already states for content coders.

**Priority**: must

## MODIFIED

### FR-032

Old: `SecurityConfig::max_kdf_work` ... SHALL bound the total key-derivation work of one operation. Accounting (below) is charged at admission, before any content block is decoded; over budget is `KdfCostExceeded`. In addition, WHEN an AES block's set-up finds the process key slot (FR-036) holding a different or unknown key than the one admission counted as cached, THE SYSTEM SHALL charge `2^power` again for each such coder; an over-budget re-charge is `KdfCostExceeded` mid-operation (`PartialExtraction` for `extract`) and the refusal is sticky for the rest of the operation. Admission SHALL refuse any power above 24 ... and SHALL sum with saturating addition.

New: `SecurityConfig::max_kdf_work` (a Rust, Python and Node setting; the CLI has no flag for it) (`NonZeroU64`, SHA-256 rounds; default 2^27) SHALL bound the key-derivation work of one operation, and the meaning is per operation: the operation's own derivations are the only ones charged. Accounting (below) is charged at admission, before any content block is decoded; over budget is `KdfCostExceeded`. There is no mid-operation re-charge, because no key slot is shared. A nested operation has its own budget and is not charged to the outer one. Admission SHALL refuse any power above 24 as FR-047 states (power `0x3F` as `WeakEncryptionRefused` per FR-031, powers 25 to `0x3E` as `KdfCostExceeded`) before computing `2^power`, and SHALL sum with saturating addition.

### FR-034

Old: the turn-based sequential decode, the release of the turn before the decoder's first source call, and the layouts that held it.

New: WHILE a 7z has AES blocks THE SYSTEM SHALL decode its blocks in archive order within one operation, so the order of derivations is the order the accounting assumes. No process-wide lock is taken. An encrypted header is read into memory before it is parsed (FR-045), so the caller's `Read`/`Seek` code never runs under a lock. The turn, its non-FIFO limit and the held-through-set-up layouts no longer exist.

### FR-036

Old: the mirror of the process key slot by a keyed fingerprint and its update rules (header identity, coder-graph full-charge rule).

New: REMOVED, replaced by FR-044 and FR-045. A block that `sevenz-rust2` may build as a coder graph is no longer charged for every AES coder in full: all AES coders of a block share one (power, salt) pair (FR-047), so the block costs at most one derivation, shared with every other block of that pair.

### FR-037

Old: admission, replay and set-up walk the AES coders in decode order; one shared charge walk; coder-graph blocks follow the full-charge rule of FR-036.

New: admission SHALL charge the budget by one walk over the AES content blocks in archive order: `2^power` for each (power, salt) pair the first time it is seen in the operation (the header pair counts as seen, FR-045). `KdfCostExceeded` SHALL be surfaced by `extract`, `verify` and `list`, including the 7z link walk. No replay and no graph-block full-charge rule remain.

### FR-040

Old: the budget counts derivations performed; a per-reader key cache upstream would remove the turn and the re-charge; the implementation PR carries a neutral upstream-report draft.

New: the budget counts derivations the operation performs, each pair once (FR-044). The per-reader key cache the old text asked for upstream is achieved locally by raw-key hand-off, so the upstream report is no longer a requirement of this feature. A public constructor for `Coder` or a derived-key API in `sevenz-rust2` would replace the donor-coder workaround and is tracked as a follow-up (enhancement, P3).

### FR-041

Old: the docs state the residual limits of the accounting section and the zeroization scope.

New: the docs state that `max_kdf_work` bounds the key-derivation work one operation performs, that nested and concurrent operations each have their own budget, and the zeroization scope of FR-044 (the 32 key bytes yes; `sevenz_rust2::Password` copies no). The residual-limits list shrinks to: other `sevenz-rust2` users in the process are outside the accounting.

### Accounting of `max_kdf_work` (section text)

Old: the consequence bullets "Concurrent operations with the same key cost nothing extra / different keys may fail each other", "A block that may be built as a coder graph is charged for every AES coder in full", "An encrypted 7z nested inside another needs a higher budget", and the residual limits (turn, FIFO, source under the turn).

New: those four bullets are removed. In their place: concurrent operations never affect each other's budget; a nested operation is charged to its own budget only (the nested-pipeline boundary of #1348 is removed on purpose); a header-encrypted 7z reserves `2^24` until the header pair is known, then the header derivation is the pair's single derivation.

### Q10 (closed note)

Old: the charge is re-charged when the shared key slot holds another key; concurrent different-key operations may fail each other.

New: the charge is taken once at admission per pair; there is no slot, no re-charge, and no interference between operations (FR-032, FR-044).

### GN-2

Old: ... derivation accounting of FR-032 and FR-036 ... and sequential AES decode under the turn (FR-034).

New: `max_kdf_work` enforced before the first content derivation, with the per-pair accounting of FR-032 and FR-037 (derivations performed, not requested), and no state shared between operations (FR-044).

### GN-3

Old: the upstream report of FR-040 is prepared as a local, neutral draft.

New: REMOVED (see FR-040).

## Edge cases (section 6 rows)

### ADDED

| Scenario | Expected Behavior |
|----------|-------------------|
| Two operations with different passwords run concurrently on encrypted 7z archives under a tight `max_kdf_work` | Both succeed; neither is charged for the other (FR-032, FR-044) |
| Encrypted 7z extracted from a sink or callback of another 7z operation | Own budget, no charge to the outer operation (FR-032) |
| 7z block whose AES coders declare different (power, salt) | The block is refused as unsupported (`InvalidArchive`); other blocks still decode; `verify` reports that block alone (FR-046, FR-047) |
| Encrypted 7z header with several AES coders | Refused as unsupported (FR-047) |
| Encrypted 7z header with power 25 to `0x3E` | `KdfCostExceeded` before any derivation (FR-047) |
| Encrypted 7z header with power `0x3F` | `WeakEncryptionRefused` (FR-047) |
| Encrypted 7z header with a bad start-header or next-header CRC | Refused before any key derivation (FR-045) |

### MODIFIED

| Scenario | Old | New |
|----------|-----|-----|
| 7z power above 24 | Rejected upstream; admission refuses powers 25 to 62 first | Admission refuses powers 25 to `0x3E` first (`KdfCostExceeded`); power `0x3F` is `WeakEncryptionRefused` |
| 7z header with a raw-key AES coder (power `0x3F`, any AES coder) | `WeakEncryptionRefused` when the probe models the header | `WeakEncryptionRefused` for the header's AES coder; an encrypted header with several AES coders is refused as unsupported first (FR-047) |

## Deviations

Approved during implementation (critic rounds, accepted by the lead):

| Item | Specified | Implemented |
|------|-----------|-------------|
| Extra dependency | `crc32fast` for header CRCs | `flate2::Crc` is used; no `crc32fast` dependency |
| Direct dependency | none new | `sha2` 0.11 added as a direct dependency of `exarch-core` (already in the lockfile) |
| CLI list-before-extract | One derivation for an encrypted-header 7z | `extract` of an encrypted-header 7z derives twice: the CLI's list-before-extract pass and the extraction are separate operations and no longer share a key (library `extract` and `list` derive once). Accepted (perf F1); a follow-up issue is filed by the reviewer |
| L1 narrowing | Mixed-pair blocks and multi-AES headers decoded | Refused as unsupported (user-approved, FR-047) |
