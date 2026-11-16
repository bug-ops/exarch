---
aliases:
  - Encrypted Archive Support
  - Password-Protected ZIP and 7z
  - Archive Passphrase Input
tags:
  - sdd
  - spec
  - encryption
  - security
  - parity
  - rust
created: 2026-11-06
updated: 2026-11-16
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Encrypted Archive Support (Password Input for ZIP and 7z)

> [!info] Metadata
> **Subsystem**: exarch-core / `formats::{zip,sevenz}`, `config`, `request`, `security` (`QuotaTracker`, `validate_compression_ratio`), error classification; surfaces in `exarch-cli`, `exarch-python`, `exarch-node`
> **MSRV**: Rust 1.100
> **Origin**: #1001 (competitive parity research, P4). Classification history: closed #83, #96, #171, #658.
> **Status**: implemented in the batch PR #1230 (branch `feat/1230-batch-11-issues`, issue #1023) and refined in the batch of #1237 to #1246 (branch `feat/1244-batch-10-issues`), unreleased. The three Ask First items of section 9 were decided by the user on 2026-11-15. The deviations that remain are listed in section 9 ("Deviations"); the requirements carry the live behavior.
> **Decision**: implement (user decision, recorded in plan rev 2; recommendations accepted 2026-11-15), read-only, not `wontfix`. The criteria of the research draft (DC-1 to DC-5) are replaced by the go/no-go criteria of section 7 that the implementation PR must meet.

## 1. Overview

### Problem Statement

exarch refuses encrypted content by policy. The README states "Solid and encrypted 7z archives are rejected for security reasons", and encrypted ZIP entries are reported as encrypted and not extracted. No surface (CLI, Rust API, Python, Node) accepts a password, so a user holding a legitimate password-protected archive and its password cannot use exarch and falls back to a tool with weaker extraction safety.

| Tool | ZIP ZipCrypto | ZIP WinZip AES | 7z AES-256 | Password input |
|------|---------------|----------------|------------|----------------|
| bsdtar / libarchive | read | read | read | `--passphrase` |
| 7-Zip | yes | yes | yes | `-p` |
| cpython `zipfile` | read (`pwd=`) | no | n/a | `extractall(pwd=...)` |
| zip crate | yes | yes (`aes-crypto` feature) | n/a | `ZipArchive::by_index_decrypt` |
| sevenz-rust2 crate | n/a | n/a | yes (AES-256/SHA-256 coder `06F10701`) | password-based decoder |
| libarchive_oxide 0.2.0 | not stated | read/write | read | file or prompt, never argv |

exarch builds zip with `default-features = false`, so AES is compiled out today; sevenz-rust2's `aes256` is already on (default features).

#### Behavior in the code today (verified 2026-11-08)

| Aspect | Current behavior |
|--------|------------------|
| Error | Any encrypted ZIP entry or 7z archive is refused as `ArchiveError::SecurityViolation` carrying `Violation::EncryptedEntry { name }` (ZIP, per entry) or `Violation::EncryptedArchive` (ZIP archive-level and 7z); machine code `SECURITY_VIOLATION`, `sub_code` `ENCRYPTED`, no `relaxable_by`. There is no `PasswordRequired`, `WrongPassword` or other encryption error type |
| Password input | None on any surface: no CLI flag, no config or request field, no binding argument. The 7z handlers open archives with `sevenz_rust2::Password::empty()`, and `is_password_error` maps upstream `PasswordRequired` and `MaybeBadPassword` to the refusal above |
| ZIP | `zip` is `~9.4` (lockfile 9.4.1) without the `aes-crypto` feature; `entry.encrypted()` is refused in list, verify and extract |
| `list` and `verify` | They refuse an encrypted ZIP the same way as `extract`; entries are not listed with an "encrypted" mark, and verify reports the refusal as an issue |
| Docs | README and the CLI skill state that encrypted 7z archives are rejected |

Enabling decryption turns exarch from "refuses opaque content" into "processes attacker-influenced ciphertext plus a secret". The upstream history shows the risk: zip 9.x fixed GHSA-8hxf-qr8p-62x4 (AES HMAC bypass on premature EOF), GHSA-c9rm-qm35-rhqf (HMAC skipped when the decompressor stops early) and GHSA-v59p-pxfc-8xvf (non-constant-time AES password verification).

### Goal

A caller who supplies the correct password can extract, list and verify password-protected ZIP and 7z archives with the same path, symlink, quota and ratio guarantees as unencrypted archives, without the password ever appearing in argv or the environment, with a bounded KDF cost, and with typed errors that separate a missing password, a wrong one and tampering.

### Decisions

| Topic | Decision (plan rev 2 and rev 3) |
|-------|-------------------------------|
| Scope v1 | Read only. ZIP WinZip AES (AE-1, AE-2; 128, 192, 256) through zip's `aes-crypto` feature; 7z AES-256/SHA-256 content and header-encrypted 7z through sevenz-rust2 0.25 (`Archive::is_file_encrypted`). ZipCrypto stays refused with a typed reason (weak cipher, 1-in-256 verifier false accepts); opt-in is a later decision. Creating encrypted archives is out of scope |
| Solid 7z | Refused independently of encryption |
| Advisory floor | zip at least 9.0.5; the workspace pins `zip = "~9.4"` (lockfile 9.4.1), which exceeds it. The three GHSA ids above are the record; no researcher step is needed |
| Bindings | Python accepts `bytearray` only; Node accepts `Buffer` only. `bytes` and `str` (Python) and strings (Node) are refused: immutable, cannot be wiped |

### Out of Scope

- Creating encrypted archives; ZipCrypto decryption (a later opt-in); PKZIP strong encryption, X.509, GPG; RAR; encrypted TAR variants.
- Password recovery or guessing; keyring or password-manager integration.
- A per-derivation KDF knob (sevenz-rust2 fixes it, FR-030).

## 2. User Stories

### US-001: Extract a password-protected ZIP
AS A user holding an AES-encrypted ZIP and its password
I WANT to supply the password out of band
SO THAT I keep exarch's traversal, symlink and quota protections

```
GIVEN a ZIP with WinZip AES-256 entries and the correct password
WHEN extract runs
THEN every entry is decrypted, validated through the standard pipeline and written
AND the report matches the unencrypted twin
```

### US-002: Extract a password-protected 7z
AS A user with a non-solid AES-256 7z
I WANT to supply its password
SO THAT it extracts like any other 7z

```
GIVEN a non-solid 7z with AES-256 content (header encrypted or not) and the correct password
WHEN extract runs
THEN entries are decrypted and validated through the standard pipeline
```

### US-003: Keep the password out of process listings and logs
AS A security-conscious operator
I WANT the password accepted only through a file, a file descriptor or an interactive prompt
SO THAT it never leaks through `ps`, shell history, `/proc/<pid>/environ` or logs

```
GIVEN the CLI
WHEN a password is passed as an argument value or an environment variable
THEN it is not accepted, and no error, log line or JSON output contains a password
```

### US-004: Distinguish a missing, wrong and tampered password
AS A tooling author
I WANT distinct machine-readable failures
SO THAT I can retry on a wrong password but quarantine tampered data

```
GIVEN an AES-encrypted archive
WHEN the password is wrong, or the ciphertext or HMAC is altered, or the data is truncated
THEN each case yields its own error on every surface (FR-020)
```

### US-005: Encryption cannot smuggle content past the pipeline
AS A maintainer
I WANT decrypted payloads validated like any other
SO THAT encryption cannot hide a traversal, a bomb or a link escape

```
GIVEN an encrypted ZIP with a "../" entry, an over-quota entry and a forged-size bomb entry, each with the correct password
WHEN extraction runs
THEN each is rejected exactly as in the unencrypted case
```

### US-006: List and verify an encrypted archive
AS A user
I WANT `list` and `verify` to work with and without a password
SO THAT I can inspect an archive before extracting

```
GIVEN an encrypted ZIP and no password
WHEN list runs
THEN names are listed and each encrypted entry is marked encrypted; verify --check-integrity counts the entries as unverified (reason encrypted, WARNING)
```

### US-007: A clear refusal without a password
AS A user who forgot the password
I WANT a stable error that says a password is needed
SO THAT I know what to do

```
GIVEN an encrypted archive and no password
WHEN extract runs
THEN PasswordRequired is returned (it replaces today's `SECURITY_VIOLATION` / `ENCRYPTED` refusal, see Q11) and the destination is untouched
```

### US-008: A hostile archive cannot burn CPU through the KDF
AS A service operator
I WANT the key-derivation work of one operation bounded
SO THAT a crafted 7z cannot cost minutes of CPU

```
GIVEN a 7z whose every block carries a different salt at power 24
WHEN extract runs with the default budget
THEN the operation fails with KdfCostExceeded before the first content derivation, having derived at most the header key
```

## 3. Functional Requirements

### Input and types

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL provide `Password` in exarch-core (using `zeroize`, a direct dependency of exarch-core behind the `encryption` feature): bytes in a zeroizing buffer, redacted `Debug`, no `Display`, no `Clone` (shared as `Arc<Password>` where needed), a constructor that refuses empty and over-long input; it is passed per request (`with_password(Option<Arc<Password>>)` on the extract, list, verify, sink-extract and memory-extract requests of [[020-reader-sink-and-in-memory-api/spec]], where `None` means no password and `Password::shared` builds the shared handle) and never stored in `SecurityConfig`, which is `Clone` and `Debug` | must |
| FR-002 | THE CLI SHALL accept the password only from `--password-file <PATH>` (a regular file, first line, trailing `\n` or `\r\n` stripped, at most 1 KiB, refused on Unix when group- or world-readable), `--password-fd <N>` (Unix) or `--password-prompt` (no-echo TTY through the `rpassword` crate, a dependency of exarch-cli only; non-interactive stdin is an error, never a hang); the flags are mutually exclusive; there SHALL be no argv value and no environment variable; WHEN `--password-fd` names a descriptor that is open but not readable (for example a write-only descriptor such as 1 or 2) THE CLI SHALL say so in its error instead of a generic read failure (#1264) | must |
| FR-003 | THE Python binding SHALL take `password: bytearray | None` and THE Node binding `password?: Uint8Array` (a `Buffer` is one); a `bytes`, `str` or string SHALL be refused with a typed error. The in-memory `list` and `verify` functions of both bindings take the password as their last parameter too, validated before the archive is read (#1256). exarch zeroizes its own copy; the caller wipes theirs (the docs show `password[:] = bytes(len(password))` and `buf.fill(0)`); zeroization across the binding boundary is best-effort and documented | must |
| FR-005 | The password, derived keys and any key material SHALL NOT appear in argv, the environment, progress callbacks, reports, JSON, error messages, logs, `Debug` output or panic payloads; grep-style tests SHALL enforce it | must |

### Pipeline

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | THE SYSTEM SHALL classify a 7z decode failure by the block that raised it, not by the archive: in a non-solid 7z that mixes AES and plain blocks, a failure in a plain block carries the same error kind and `sub_code` as in an all-plain 7z, and a failure in an AES block stays `WrongPasswordOrCorrupt`; a failure outside any block (container hand-over) is classified as plain. THE SYSTEM SHALL order work as decrypt, then decompress, then the existing pipeline unchanged: `SafePath` on names (including names decrypted from a 7z header), quotas and the compression ratio on decrypted, decompressed sizes, with the ciphertext overhead subtracted from the compressed size; no declared size from the encrypted container is trusted | must |
| FR-011 | EVERY decrypted entry SHALL be read to its end so the AES HMAC is always checked (the GHSA-8hxf class), before the atomic rename publishes it; unauthenticated plaintext SHALL NOT be released to the destination | must |
| FR-012 | The solid 7z policy SHALL apply independently of encryption (spec 002 FR-044) | must |
| FR-013 | Decryption SHALL sit behind an additive `encryption` Cargo feature of exarch-core (zip `aes-crypto`), enabled by exarch-cli and the bindings; a default core build keeps AES compiled out; wasm targets SHALL keep building | must |
| FR-014 | `list` and `verify` SHALL follow [[019-verify-and-list-model/spec]]. ZIP names are plaintext, so `list` works without a password. `list` marks encrypted entries: core `ArchiveEntry.encryption` is the `#[non_exhaustive]` enum `EntryEncryption { Plain, Encrypted }` (token `plain` or `encrypted`), set for every entry whether or not a password was given (ZIP from the entry header's encryption flag; 7z `Encrypted` when the entry's block has an AES coder, so an empty file or directory is `Plain` unless it falls inside an AES block's run; TAR always `Plain`); the CLI `--json` entries carry a boolean `encrypted` (always present), the human `list -l` line ends with `(encrypted)`, and Python `ArchiveEntry.encrypted` and Node `encrypted` (on every kind interface) are booleans. `verify --check-integrity` without a password counts encrypted entries as unverified (`UnverifiedReason::Encrypted`, token `encrypted`, WARNING, `IntegrityStatus::Incomplete`) and with one decrypts and checks. This holds for a 7z with AES content under a plain header as for an AES ZIP: without a password `verify` reports each file of the AES block as unverified with reason `encrypted` (WARNING, exit 0, no `ENCRYPTED` issue), while `extract` of it still fails with `password_required` before anything is written. A 7z with a plain header lists without a password; one with an encrypted header is `password_required` for every command. WHEN a `verify` password is wrong for an AES 7z block THE SYSTEM SHALL report each affected entry as an `ENCRYPTED` issue with reason `wrong_password_or_corrupt`, as `extract` does, mark the remaining entries of that block as not verified, and continue with the later blocks; the failure of one block does not stop `verify` (#1248) | must |
| FR-015 | WHEN an archive mixes encrypted and unencrypted entries THE SYSTEM SHALL handle each by its own state, and a failure SHALL follow the existing atomic and partial extraction policies. WHEN the entry selection of an `extract` (library and CLI) extracts no encrypted ZIP entry, THE SYSTEM SHALL NOT demand a password: an encrypted entry that the selection does not certainly extract (a file, a symlink or a directory entry) is routed by its name only through a sealed route, so its path error or skip equals that of its unencrypted twin, and its payload is never read; an entry skipped only by the extension allowlist still needs the password. An entry the selection extracts keeps `password_required`, `wrong_password` and the other refusals of FR-020, and a selected entry whose name is invalid fails with its path error at that entry. The relaxation applies only to the list pass that precedes `extract`: standalone `list` and `verify` still check a supplied password against every encrypted entry. ZipCrypto stays `WeakEncryptionRefused` at open, even for an unselected entry (#1261) | should |

### Errors

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | Errors SHALL be typed as `Violation::Encrypted { reason: EncryptionRefusal, name: Option<..> }` (`EncryptionRefusal` is a `#[non_exhaustive]` closed enum with snake_case tokens; `ArchiveError::encryption_refusal()` returns it), machine code `SECURITY_VIOLATION` with `sub_code` `ENCRYPTED` (the bindings' `SecurityViolationSubCode` stays stable; a plain `PasswordRequired` keeps `SECURITY_VIOLATION`), with these reasons: `PasswordRequired` (no password; replaces today's `Violation::EncryptedArchive` and `EncryptedEntry` refusal), `WrongPassword` (ZIP AES verifier mismatch), `AuthenticationFailed` (HMAC mismatch: tampered, or a wrong password that passed the 2-byte verifier), `WrongPasswordOrCorrupt` (7z has no verifier: a supplied password plus a CRC or decoder failure), `WeakEncryptionRefused` (ZipCrypto, and 7z "raw key" mode, FR-031), `KdfCostExceeded` (FR-032), `UnusablePassword` (a 7z that has an AES block or an encrypted header and was given a password that is not valid UTF-8, which cannot be encoded as the UTF-16LE 7z needs; ZIP is unaffected). Distinguishing wrong from tampered is accepted: whoever holds the archive can guess offline anyway, and rate limiting belongs to the caller. The reason is machine-readable on every surface: the `--json` error `reason` key, the Python `SecurityViolationError.reason` attribute and the Node error `reason` property, with the snake_case tokens `password_required`, `wrong_password`, `authentication_failed`, `wrong_password_or_corrupt`, `weak_encryption_refused`, `kdf_cost_exceeded`, `unusable_password`. On every 7z path (content block and encrypted header) the refusals are checked in one order, and the first that applies wins: `password_required`, `unusable_password`, `weak_encryption_refused`, `kdf_cost_exceeded`. The `unusable_password` refusal is raised during admission, before any decode | must |

### KDF cost

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | Per derivation, THE SYSTEM SHALL inherit sevenz-rust2 0.25's bound: `NumCyclesPower` above 24 (`MAX_AES_CYCLES_POWER`, `encryption/aes.rs`) is rejected upstream, at most 2^24 SHA-256 rounds. For a header-encrypted 7z the key is derived inside `Archive::read`, before exarch sees any coder, so v1 has no per-derivation knob; a test pins the upstream cap | must |
| FR-031 | Power `0x3F` ("raw key" mode, no KDF) in a content coder SHALL be refused as `WeakEncryptionRefused`, detected from the coder properties during admission. It cannot be refused for an encrypted header before the header is read, because the key is built inside `Archive::read`, and after the read exarch no longer sees the header coder properties, so the check is made by the header probe instead: WHEN the probe models the encoded header, ANY AES coder of it (every coder with the AES method id, not only the first) whose properties select raw-key mode (power `0x3F`) SHALL be refused as `WeakEncryptionRefused` in `list`, `verify` and `extract`, given a UTF-8 password, before `Archive::read`; with no password it stays `PasswordRequired` (FR-020 order). Coder properties that do not parse count as a derived key. WHEN the probe does not model the header (unmodelled or not applicable) behavior is unchanged and no raw-key check is claimed; refusing it there would need an upstream change. Raw-key mode runs no KDF, so it adds no CPU risk; it only means the key is the password bytes themselves | must |
| FR-032 | `SecurityConfig::max_kdf_work` (a Rust, Python and Node setting; the CLI has no flag for it) (`NonZeroU64`, SHA-256 rounds; default 2^27) SHALL bound the total key-derivation work of one operation. Accounting (below) is charged at admission, before any content block is decoded; over budget is `KdfCostExceeded`. Admission SHALL refuse any power above 24 (power `0x3F` as `WeakEncryptionRefused` per FR-031, powers 25 to 62 as `KdfCostExceeded`) before computing `2^power`, and SHALL sum with saturating addition | must |
| FR-033 | ZIP AES uses PBKDF2-HMAC-SHA1 at a fixed 1000 iterations per entry; its cost is bounded by `max_file_count`, stated in the docs and not charged against `max_kdf_work` | must |
| FR-034 | WHILE a 7z has AES blocks THE SYSTEM SHALL decode those blocks sequentially (no parallel decode of encrypted blocks), so the order of derivations is the archive order the accounting assumes | must |
| FR-035 | WHEN a 7z has an encrypted header THE SYSTEM SHALL bound the header before it is decoded: the declared unpack sizes of the encoded header and its raw record SHALL be checked against the per-entry size cap before parsing, and the parse SHALL then run under `max_decoder_memory`, exactly as for a plain encoded header. A header too large for those limits, or whose decoder would exceed the memory limit, SHALL be reported as a quota refusal and never as a wrong password (the memory-limit verdict is taken before the encrypted-header verdict); a parse failure with a password that stays within the limits remains `WrongPasswordOrCorrupt` (#1262) | must |

#### Accounting of `max_kdf_work`

The budget bounds the key-derivation work that an operation requests (FR-032). Admission walks the AES content blocks in archive order and charges `2^power` for each requested derivation; consecutive blocks that declare the same (power, salt) pair request one derivation, and the first content block always counts. For a header-encrypted 7z, `2^24` is reserved up front for the header derivation, which exarch cannot observe.

Consequences:

- A default-config encrypted 7z has one block per file (`SolidArchives::Refuse`). A local `7z` run (`7z a -t7z -ms=off -mhc=off -p...`, 4 files) writes one (power, empty salt) pair for every block, so such an archive requests one derivation at any file count; the plaintext-twin test with 300 files pins this.
- An archive whose blocks declare many distinct pairs is charged for each change and fails with `KdfCostExceeded` before the first content derivation once the budget is spent. A writer that uses a distinct salt per file therefore meets a file-count limit at `max_kdf_work / 2^power` blocks; `max_kdf_work` raises it, and the default is accepted as documented (Q4).

### Dependencies and a possible refinement

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | The budget of FR-032 counts requested derivations. A per-reader key cache in the upstream 7z library is a possible later refinement of that accounting; the implementation PR SHALL carry a local, neutral upstream-report draft, and filing it is an outward action that needs the user's go | must |
| FR-041 | THE DOCS SHALL state that `max_kdf_work` bounds the key-derivation work an operation requests, and that the zeroization requirement of FR-001 and FR-005 is scoped to buffers exarch owns (its password copy). The zip crate wipes AES round keys and key streams on drop (zip 9.x, PRs 1196 and 1204) | must |
| FR-042 | The zip dependency floor SHALL include the fixes for GHSA-8hxf-qr8p-62x4 (patched 9.0.0), GHSA-c9rm-qm35-rhqf (9.0.1) and GHSA-v59p-pxfc-8xvf (9.0.5): zip at least 9.0.5 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Plaintext reaches the destination only after per-entry authentication succeeds (ZIP AES HMAC) or integrity is verified (7z CRC); no streaming of unauthenticated plaintext |
| NFR-002 | Security | Password verification, MAC checks and key derivation use the dependencies' constant-time primitives; exarch adds no timing oracle beyond the classification of FR-020 |
| NFR-003 | Security | KDF work per operation is bounded by FR-030 to FR-034; the budget semantics of FR-041 are documented |
| NFR-004 | Resource limits | Memory and quota behavior of decrypted entries equals unencrypted entries; decryption adds no unbounded buffering |
| NFR-005 | Performance | The throughput of unencrypted archives regresses by less than 10%; the decryption overhead target is not set (Q6) |
| NFR-006 | Compatibility | Interoperable with 7-Zip and libarchive archives for the supported methods |
| NFR-007 | Maintainability | All security logic stays in `exarch-core`; bindings only map types and errors |
| NFR-008 | Dependencies | `cargo deny --all-features check` is clean; the direct dependencies `zeroize` (core) and `rpassword` (cli) are the decided additions of section 9; any other new one is Ask First |
| NFR-009 | Testing | Correct and wrong password, truncated and bit-flipped ciphertext, forged sizes, traversal and bomb payloads inside encrypted entries, mixed-entry archives, KDF-bomb archives (distinct salt per block, power above 24, power `0x3F`), per format |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Password` | Opaque secret, per request | zeroizing bytes, redacted `Debug`, no `Clone`, non-empty, length-bounded |
| `PasswordSource` (CLI) | Channel the password is read from | file path, file descriptor, prompt |
| `max_kdf_work` | `SecurityConfig` field | `NonZeroU64` rounds, default 2^27 |
| Derivation run | Accounting unit (FR-032) | (power, salt) pair changed since the previous AES block |
| Encryption error family | `sub_code` `ENCRYPTED` | `PasswordRequired`, `WrongPassword`, `AuthenticationFailed`, `WrongPasswordOrCorrupt`, `WeakEncryptionRefused`, `KdfCostExceeded`, `UnusablePassword` |
| `EntryEncryption` | Per-entry marker on `ArchiveEntry` | `Plain` (default), `Encrypted`; token `plain` or `encrypted`; a boolean `encrypted` on the CLI JSON, Python and Node surfaces |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Wrong password, WinZip AES | `WrongPassword`; destination untouched |
| Wrong password that passes the 2-byte verifier | `AuthenticationFailed` (HMAC) |
| 7z with a wrong password | `WrongPasswordOrCorrupt` (no verifier) |
| AES ciphertext truncated (premature EOF) | `AuthenticationFailed`; no plaintext released |
| Declared size forged in an encrypted entry | Ratio and quota on actual decrypted bytes; rejected as unencrypted |
| Encrypted entry with `../`, absolute path or link escape | Rejected by the standard pipeline after decryption |
| 7z power above 24 | Rejected upstream; admission refuses powers 25 to 62 first (`KdfCostExceeded`) |
| 7z content coder at power `0x3F` | `WeakEncryptionRefused` |
| 7z header with a raw-key AES coder (power `0x3F`, in any of its AES coders) | `WeakEncryptionRefused` when the probe models the header, before `Archive::read`; no password stays `PasswordRequired` |
| Distinct salt per block | `KdfCostExceeded` after at most `max_kdf_work / 2^power` runs (minus the header reservation) |
| Header-encrypted 7z, no password | `PasswordRequired` for list, verify and extract |
| Solid and encrypted 7z | Refused as solid regardless of password |
| ZipCrypto entry | `WeakEncryptionRefused` |
| Password file missing, unreadable, over 1 KiB or group/world-readable (Unix) | CLI error before any archive access |
| Password with a trailing newline in the file | One trailing `\n` or `\r\n` stripped |
| 7z password that is not valid UTF-8, archive with an AES block or an encrypted header | `UnusablePassword`, before any decode; order `password_required`, `unusable_password`, `weak_encryption_refused`, `kdf_cost_exceeded` |
| 7z with AES content under a plain header, no password | `verify` unverified `encrypted` (WARNING); `extract` `PasswordRequired` |
| Non-solid 7z mixing one AES block and one plain block, plain block corrupted, right password | Same error kind and `sub_code` as the same corruption in an all-plain 7z; a corrupted AES block stays `WrongPasswordOrCorrupt` |
| `list` of an archive with encrypted entries | Each encrypted entry is marked (`encrypted` true, `(encrypted)` in `list -l`) |
| Empty password | Refused at construction |
| Prompt requested with non-interactive stdin | Error, no hang |
| Python `bytes` or `str`, Node string | Refused with a typed error |
| Atomic extraction fails on authentication | Existing atomic rollback |

## 7. Success Criteria

### Go/no-go criteria

The implementation PR meets all of these or does not merge:

| ID | Criterion |
|----|-----------|
| GN-1 | zip at least 9.0.5 (GHSA-8hxf-qr8p-62x4, GHSA-c9rm-qm35-rhqf, GHSA-v59p-pxfc-8xvf) |
| GN-2 | `max_kdf_work` enforced before the first content derivation, with the run accounting of FR-032 and sequential AES decode (FR-034) |
| GN-3 | The upstream report of FR-040 is prepared as a local, neutral draft; nothing is filed without the user's go |
| GN-4 | No password in argv, environment, logs, `Debug`, errors or JSON (grep tests) |
| GN-5 | (met: `tests/fixtures/enc-many.7z`, 300 non-solid AES files, with a test at the default budget and one at a budget of exactly one derivation) Plaintext-twin property test: an encrypted archive extracts to exactly what its plaintext twin extracts to, including a many-file non-solid 7z written by the local `7z` (well beyond 224 files) |
| GN-6 | Unencrypted throughput regression under 10% |
| GN-7 | `cargo deny` clean |
| GN-8 | Fuzz target over encrypted ZIP and 7z inputs; bindings refuse `str`, `bytes` and strings |

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Archives from 7-Zip (and bsdtar where supported) extract byte-identically with the correct password | 100% of the fixture matrix |
| SC-002 | Traversal, symlink, bomb and quota payloads inside encryption | Rejected identically to unencrypted |
| SC-003 | Password occurrences in argv, environment, logs, JSON, error text, Python and Node `repr` | 0 |
| SC-004 | Bit-flipped or truncated AES payloads that release plaintext | 0 across the fuzz corpus |
| SC-005 | Fixtures | Generated by the local `7z` (`7z a -tzip -mem=AES256 -p...`, `7z a -p... -mhe=on`) through a committed generator script, plus hand-built KDF-bomb and truncated-AES-entry archives |

## 8. Agent Boundaries

### Always (without asking)
- Run the full CI-parity gate suite and `rust-security-maintenance` after any change in this area.
- Keep all security logic in `exarch-core`; keep bindings thin.
- Update `skills/exarch-cli/SKILL.md` when flags, exit codes or JSON change, verified against the running binary.

### Ask First
- Enabling any new zip feature beyond `aes-crypto`, or changing zip or sevenz-rust2 versions or features.
- Allowing ZipCrypto in any form.
- Changing the public error taxonomy or the `max_kdf_work` default.

### Never
- Accept a password via argv or an environment variable.
- Log, serialize, print or include a password or key in any output or panic message.
- Release unauthenticated plaintext, or bypass `SafePath`, quota or ratio checks for decrypted content.
- Add password guessing or recovery.
- Edit `specs/` by hand or commit directly to `main`.

## 9. Open Questions

> [!success] Ask First items resolved (user, 2026-11-15)
> 1. **Prompt dependency**: `rpassword` in exarch-cli only (no `unsafe` on Windows).
> 2. **`zeroize`**: a new direct dependency of exarch-core, behind the `encryption` feature.
> 3. **`max_kdf_work` on the CLI**: no flag; it stays a Rust, Python and Node setting.

> [!question] Left open
> - **Q4**: the `max_kdf_work` default (2^27) is confirmed only against the local `7z`, which writes one salt (empty) per archive; the file-count cliff for a writer with a salt per file is accepted and documented.
> - **Q6**: no decryption overhead target is set; the `Password` maximum length is the file limit of 1 KiB.

> [!success] Closed by the implementation
> - **Q5**: an encrypted 7z header is detected on open and refused as `password_required` without a password; `2^24` is reserved against `max_kdf_work` before the parse; any parse failure with a password is `WrongPasswordOrCorrupt`.
> - **Q7**: admission refuses powers 25 to 62 as `KdfCostExceeded` and power `0x3F` in a content coder as `WeakEncryptionRefused`.
> - **Q8**: a password supplied for an archive with no encrypted entries is ignored.
> - **Q9**: `list` works without a password for a 7z with a plain header; a header-encrypted 7z is `password_required` for every command.
> - **Q10**: the KDF charge is taken once at admission, before any block is decoded, and counts requested derivations (FR-032); an upstream per-reader cache is a possible later refinement (FR-040).
> - **Q12**: an encrypted 7z header is limited like a plain one: declared sizes against the entry cap before parsing, then the parse under `max_decoder_memory`; exceeding either is a quota refusal, not `wrong_password_or_corrupt` (FR-035).
> - **Q11**: the reasons are `Violation::Encrypted` variants under `SECURITY_VIOLATION` with sub-code `ENCRYPTED` (see FR-020).

### Deviations (approved by the lead during the batch)

| Requirement | Specified | Implemented |
|-------------|-----------|-------------|
| FR-020 | `Violation::Encryption(EncryptionRefusal)` | `Violation::Encrypted { reason, name }`, reason exposed on every surface |
| FR-003 | Node `Buffer` | `Uint8Array` (a `Buffer` is accepted) |
| FR-004 | typed refusal for a non-UTF-8 7z password | `WrongPasswordOrCorrupt` |
| FR-002 | `--password-fd` | reads `/dev/fd/N` (no `unsafe`) and keeps the descriptor open until exit |
| FR-013 | additive feature | the module is always compiled; the feature gates `Password` |
| FR-016 | in-memory API | `SinkExtractRequest::with_password` exists; `MemoryExtractRequest` and the binding `*_to_memory` functions take no password (follow-up) |
| FR-014 | verify stops at the first failing AES block | verify records a per-entry issue for the failing block, marks the rest of that block as not verified, and continues with later blocks (more information than extract, no weaker) |
| FR-015 | selection scope counts an unresolvable name as selected | every encrypted entry the selection does not certainly extract is read raw and routed by name, so its path error equals the plain twin; a selected entry with an invalid name fails with its path error at that entry |
| FR-010 | decrypt then the unchanged pipeline | an AES ZIP entry with a data descriptor is checked by the same signature scan as stored data, before any write |

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — validation pipeline decrypted content traverses
- [[002-format-handlers/spec]] — 7z and ZIP handlers, solid policy (FR-044)
- [[019-verify-and-list-model/spec]] — list and verify model
- [[020-reader-sink-and-in-memory-api/spec]] — in-memory API and request types
- [[025-cli-landlock-sandbox/spec]] — the sandbox grant never widens for a password source
- [zip-rs/zip2](https://github.com/zip-rs/zip2) — advisories GHSA-8hxf-qr8p-62x4, GHSA-c9rm-qm35-rhqf, GHSA-v59p-pxfc-8xvf
- [sevenz-rust2](https://github.com/hasenbanck/sevenz-rust2) 0.25.0 — `encryption/aes.rs` (`MAX_AES_CYCLES_POWER`)
- Issue #1001; closed classification history #83, #96, #171, #658
