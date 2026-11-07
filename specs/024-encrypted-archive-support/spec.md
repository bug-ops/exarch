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
updated: 2026-11-06
status: draft
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
> **MSRV**: Rust 1.99.1
> **Origin**: #1001 (competitive parity research, P4). Classification history: closed #83, #96, #171, #658.
> **Status**: draft (spec-only change; it describes no behavior that is in the code), implementation-ready after the Ask First items in section 9 are resolved. It is NOT ready while any of them is open: the implementation PR must not start, and this status must not change, until the user has decided the three items of section 9 (prompt dependency, `zeroize`, `max_kdf_work` on the CLI).
> **Decision**: implement (user decision, recorded in plan rev 2), read-only, not `wontfix`. The criteria of the research draft (DC-1 to DC-5) are replaced by the go/no-go criteria of section 7 that the implementation PR must meet.

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

exarch builds zip with `default-features = false`, so AES is compiled out today; sevenz-rust2's `aes256` is already on.

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
THEN names are listed with encrypted entries marked; verify --check-integrity counts them as unverified (reason encrypted)
```

### US-007: A clear refusal without a password
AS A user who forgot the password
I WANT a stable error that says a password is needed
SO THAT I know what to do

```
GIVEN an encrypted archive and no password
WHEN extract runs
THEN PasswordRequired is returned (today's refusal, unchanged) and the destination is untouched
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
| FR-001 | THE SYSTEM SHALL provide `Password` in exarch-core: bytes in a zeroizing buffer, redacted `Debug`, no `Display`, no `Clone` (shared as `Arc<Password>` where needed), a constructor that refuses empty and over-long input; it is passed per request (`with_password` on the extract, list and verify requests of [[020-reader-sink-and-in-memory-api/spec]]) and never stored in `SecurityConfig`, which is `Clone` and `Debug` | must |
| FR-002 | THE CLI SHALL accept the password only from `--password-file <PATH>` (a regular file, first line, trailing `\n` or `\r\n` stripped, at most 1 KiB, refused on Unix when group- or world-readable), `--password-fd <N>` (Unix) or `--password-prompt` (no-echo TTY; non-interactive stdin is an error, never a hang); the flags are mutually exclusive; there SHALL be no argv value and no environment variable | must |
| FR-003 | THE Python binding SHALL take `password: bytearray | None` and THE Node binding `password?: Buffer`; a `bytes`, `str` or string SHALL be refused with a typed error. exarch zeroizes its own copy; the caller wipes theirs (the docs show `password[:] = bytes(len(password))` and `buf.fill(0)`); zeroization across the binding boundary is best-effort and documented | must |
| FR-004 | Encoding: ZIP SHALL use the password bytes as given; 7z SHALL use the UTF-16LE of the text, so a 7z password must be valid UTF-8 (typed refusal otherwise); there is no Unicode normalization (as 7-Zip) | must |
| FR-005 | The password, derived keys and any key material SHALL NOT appear in argv, the environment, progress callbacks, reports, JSON, error messages, logs, `Debug` output or panic payloads; grep-style tests SHALL enforce it | must |

### Pipeline

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | THE SYSTEM SHALL order work as decrypt, then decompress, then the existing pipeline unchanged: `SafePath` on names (including names decrypted from a 7z header), quotas and the compression ratio on decrypted, decompressed sizes, with the ciphertext overhead subtracted from the compressed size; no declared size from the encrypted container is trusted | must |
| FR-011 | EVERY decrypted entry SHALL be read to its end so the AES HMAC is always checked (the GHSA-8hxf class), before the atomic rename publishes it; unauthenticated plaintext SHALL NOT be released to the destination | must |
| FR-012 | The solid 7z policy SHALL apply independently of encryption (spec 002 FR-044) | must |
| FR-013 | Decryption SHALL sit behind an additive `encryption` Cargo feature of exarch-core (zip `aes-crypto`), enabled by exarch-cli and the bindings; a default core build keeps AES compiled out; wasm targets SHALL keep building | must |
| FR-014 | `list` and `verify` SHALL follow [[019-verify-and-list-model/spec]]: ZIP names are plaintext, so `list` works without a password and marks encrypted entries; `verify --check-integrity` without a password counts them as unverified (reason `encrypted`) and with one decrypts and checks; a header-encrypted 7z without a password is `PasswordRequired` for every command | must |
| FR-015 | WHEN an archive mixes encrypted and unencrypted entries THE SYSTEM SHALL handle each by its own state, and a failure SHALL follow the existing atomic and partial extraction policies | should |
| FR-016 | The in-memory reader and sink API of spec 020 SHALL apply the same decrypt-then-validate rules and RAM accounting to decrypted bytes | should |

### Errors

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | Errors SHALL be typed, in a `sub_code` family `ENCRYPTED`: `PasswordRequired` (no password; today's refusal), `WrongPassword` (ZIP AES verifier mismatch), `AuthenticationFailed` (HMAC mismatch: tampered, or a wrong password that passed the 2-byte verifier), `WrongPasswordOrCorrupt` (7z has no verifier: a supplied password plus a CRC or decoder failure), `WeakEncryptionRefused` (ZipCrypto, and 7z "raw key" mode, FR-031), `KdfCostExceeded` (FR-032). Distinguishing wrong from tampered is accepted: whoever holds the archive can guess offline anyway, and rate limiting belongs to the caller | must |

### KDF cost

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | Per derivation, THE SYSTEM SHALL inherit sevenz-rust2 0.25's bound: `NumCyclesPower` above 24 (`MAX_AES_CYCLES_POWER`, `encryption/aes.rs`) is rejected upstream, at most 2^24 SHA-256 rounds, about 0.4 s. For a header-encrypted 7z the key is derived inside `Archive::read`, before exarch sees any coder, so v1 has no per-derivation knob; a test pins the upstream cap | must |
| FR-031 | Power `0x3F` ("raw key" mode, no KDF) in a content coder SHALL be refused as `WeakEncryptionRefused`, detected from the coder properties during admission. It cannot be refused for an encrypted header before the header is read, because the key is built inside `Archive::read`, and after the read exarch no longer sees the header coder properties, so v1 has no check there and claims none; refusing it would need an upstream change (a hook or an error for raw-key mode in `Archive::read`). Raw-key mode runs no KDF, so it adds no CPU risk; it only means the header key is the password bytes themselves. This policy applies to content only | must |
| FR-032 | `SecurityConfig::max_kdf_work` (`NonZeroU64`, SHA-256 rounds; default 2^27) SHALL bound the total key-derivation work of one operation. Accounting (below) is charged at admission, before any content block is decoded; over budget is `KdfCostExceeded`. Admission SHALL refuse any power above 24 (power `0x3F` as `WeakEncryptionRefused` per FR-031, powers 25 to 62 as `KdfCostExceeded`) before computing `2^power`, and SHALL sum with saturating addition | must |
| FR-033 | ZIP AES uses PBKDF2-HMAC-SHA1 at a fixed 1000 iterations per entry; its cost is bounded by `max_file_count`, stated in the docs and not charged against `max_kdf_work` | must |
| FR-034 | WHILE a 7z has AES blocks THE SYSTEM SHALL decode those blocks sequentially (no parallel decode of encrypted blocks), so the order of derivations is the archive order the accounting assumes | must |

#### Accounting of `max_kdf_work` (resolves the round-2 critique S1)

The budget counts derivations that actually cost, mirroring upstream's key cache, which was verified in sevenz-rust2 0.25.0 `encryption/aes.rs` (`derive_key_cached`): one process-global slot holding only the last key, keyed by a fingerprint of (`num_cycles_power`, salt length, salt, password). The AES IV is not part of the key. Admission therefore walks the AES content blocks in archive order and charges `2^power` each time the pair (power, salt) differs from the previous block's pair (a "derivation run"); a block with the same pair as its predecessor is free, as it is a cache hit. The first content block always counts as a new run. For a header-encrypted 7z, `2^24` is reserved up front for the header derivation, which exarch cannot observe (worst case, at most one derivation).

Consequences:

- A default-config encrypted 7z has one block per file (`SolidArchives::Refuse`). Counting every block would exhaust the budget after about 224 files at power 19 and fail the plaintext-twin test; counting runs does not. Evidence from a local `7z` run (`7z a -t7z -ms=off -mhc=off -p...`, 4 files): 4 blocks, each `LZMA2` plus `7zAES` at power 19, salt size 0 and a different 16-byte IV per block, so every block has the same (power, empty salt) and the archive costs one derivation, at any file count.
- A hostile archive with a distinct salt per block, or alternating two salts, is charged `2^power` for every change, up to `2^24` each: the default budget `2^27` stops it after 7 runs at power 24 once the header's `2^24` is reserved (about 2.8 s of derivation, plus the header run) and fails with `KdfCostExceeded` before the first content derivation. At 7-Zip's power 19 the same budget allows 256 distinct runs.
- An archive from a writer that uses a distinct salt per file therefore hits a file-count cliff at `2^27 / 2^power` blocks; `max_kdf_work` raises it, and the default is to be confirmed against such writers (section 9, Q4).
- The accounting walks the blocks once, but exarch reads 7z blocks more than once per operation (the link pre-pass `walk_sevenz_links` in `formats/sevenz/links.rs`, then extraction or the integrity pass), so with alternating salts the real derivation work is about the number of passes times the charged amount, unless the passes share derivations; this is an open point (Q10).
- Residual until upstream ships a per-reader cache (FR-040): the cache is process-global and holds one slot, so another operation running in the same process with a different key evicts it, and a later block of this operation re-derives without being charged. The extra cost is bounded by the block count (at most `max_file_count`) times one derivation per interleaving, and is caused by concurrent operations of the same process, not by the archive alone. The docs state it; a service should not run untrusted encrypted 7z concurrently with a large `max_file_count`.

### Upstream key cache and dependencies

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | sevenz-rust2 keeps the last derived key in a `static Mutex<Option<..>>` without zeroizing it and calls `.unwrap()` on the lock. The implementation PR SHALL NOT merge before an upstream issue or PR exists (zeroize on replace; a per-reader cache instead of a process-global one, without `unwrap`) | must |
| FR-041 | Until that ships, THE DOCS SHALL state the residual: the last 7z key stays in process memory until the next derivation or process exit. The zeroization requirement of FR-001 and FR-005 is scoped to buffers exarch owns (its password copy). The lock can be poisoned only by a panic inside `derive_key`, which has none, and the bindings' panic boundary covers it anyway. The zip crate wipes AES round keys and key streams on drop (zip 9.x, PRs 1196 and 1204) | must |
| FR-042 | The zip dependency floor SHALL include the fixes for GHSA-8hxf-qr8p-62x4 (patched 9.0.0), GHSA-c9rm-qm35-rhqf (9.0.1) and GHSA-v59p-pxfc-8xvf (9.0.5): zip at least 9.0.5 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Plaintext reaches the destination only after per-entry authentication succeeds (ZIP AES HMAC) or integrity is verified (7z CRC); no streaming of unauthenticated plaintext |
| NFR-002 | Security | Password verification, MAC checks and key derivation use the dependencies' constant-time primitives; exarch adds no timing oracle beyond the classification of FR-020 |
| NFR-003 | Security | KDF work per operation is bounded by FR-030 to FR-034; the residual of FR-040 is documented |
| NFR-004 | Resource limits | Memory and quota behavior of decrypted entries equals unencrypted entries; decryption adds no unbounded buffering |
| NFR-005 | Performance | The throughput of unencrypted archives regresses by less than 10%; the decryption overhead target is not set (Q6) |
| NFR-006 | Compatibility | Interoperable with 7-Zip and libarchive archives for the supported methods |
| NFR-007 | Maintainability | All security logic stays in `exarch-core`; bindings only map types and errors |
| NFR-008 | Dependencies | `cargo deny --all-features check` is clean; new direct dependencies follow the Ask First rule (section 9) |
| NFR-009 | Testing | Correct and wrong password, truncated and bit-flipped ciphertext, forged sizes, traversal and bomb payloads inside encrypted entries, mixed-entry archives, KDF-bomb archives (distinct salt per block, power above 24, power `0x3F`), per format |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Password` | Opaque secret, per request | zeroizing bytes, redacted `Debug`, no `Clone`, non-empty, length-bounded |
| `PasswordSource` (CLI) | Channel the password is read from | file path, file descriptor, prompt |
| `max_kdf_work` | `SecurityConfig` field | `NonZeroU64` rounds, default 2^27 |
| Derivation run | Accounting unit (FR-032) | (power, salt) pair changed since the previous AES block |
| Encryption error family | `sub_code` `ENCRYPTED` | `PasswordRequired`, `WrongPassword`, `AuthenticationFailed`, `WrongPasswordOrCorrupt`, `WeakEncryptionRefused`, `KdfCostExceeded` |

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
| 7z header at power `0x3F` | Not refusable by exarch in v1 (the key is built inside `Archive::read` and the header coder is not visible afterwards); needs an upstream change; content policy only |
| Distinct salt per block | `KdfCostExceeded` after at most `max_kdf_work / 2^power` runs (minus the header reservation) |
| Header-encrypted 7z, no password | `PasswordRequired` for list, verify and extract |
| Solid and encrypted 7z | Refused as solid regardless of password |
| ZipCrypto entry | `WeakEncryptionRefused` |
| Password file missing, unreadable, over 1 KiB or group/world-readable (Unix) | CLI error before any archive access |
| Password with a trailing newline in the file | One trailing `\n` or `\r\n` stripped |
| 7z password that is not valid UTF-8 | Typed refusal |
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
| GN-3 | The upstream sevenz-rust2 key-cache issue is filed (FR-040) |
| GN-4 | No password in argv, environment, logs, `Debug`, errors or JSON (grep tests) |
| GN-5 | Plaintext-twin property test: an encrypted archive extracts to exactly what its plaintext twin extracts to, including a many-file non-solid 7z written by the local `7z` (well beyond 224 files) |
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
- The three items of section 9.
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

> [!warning] Ask First items: block the implementation and the "ready" status
> Each needs the user's decision before the implementation PR starts. This spec stays "draft" until all three are resolved.
> 1. **Prompt dependency**: `rpassword` in exarch-cli only, or rustix termios plus a Windows console path. The latter needs `unsafe` on Windows, which the workspace denies.
> 2. **`zeroize`** as a new direct dependency of exarch-core (not in the dependency tree today).
> 3. **`max_kdf_work` on the CLI**: whether it gets a flag (and its name), or stays a Rust, Python and Node setting only.

> [!question] Left open by the plan
> - **Q4**: the `max_kdf_work` default (2^27) is confirmed only against the local `7z`, which writes one salt (empty) per archive. Confirm against other 7z writers that use a salt per file, or accept the documented cliff.
> - **Q5**: how exarch detects an encrypted 7z header (for the 2^24 reservation of FR-032) and how a failed header decryption with a wrong password is classified (`WrongPasswordOrCorrupt` is stated for content only).
> - **Q6**: the decryption overhead target and the `Password` maximum length are not set (the file limit is 1 KiB).
> - **Q7**: the typed reason for admission refusing powers 25 to 62 (this spec uses `KdfCostExceeded`; the plan names none).
> - **Q8**: behavior when a password is supplied for an archive with no encrypted entries (ignore, or warn); the research draft left it open and the plan is silent.
> - **Q9**: whether `list` without a password should also work for header-encrypted 7z (the plan says `PasswordRequired`, so no).
> - **Q10**: how the `max_kdf_work` accounting covers the several passes over the blocks (charge per pass, or arrange that derivations are shared); found when aligning this spec with the code on 2026-11-07, not covered by the plan.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — validation pipeline decrypted content traverses
- [[002-format-handlers/spec]] — 7z and ZIP handlers, solid policy (FR-044)
- [[019-verify-and-list-model/spec]] — list and verify model
- [[020-reader-sink-and-in-memory-api/spec]] — in-memory API and request types
- [zip-rs/zip2](https://github.com/zip-rs/zip2) — advisories GHSA-8hxf-qr8p-62x4, GHSA-c9rm-qm35-rhqf, GHSA-v59p-pxfc-8xvf
- [sevenz-rust2](https://github.com/hasenbanck/sevenz-rust2) 0.25.0 — `encryption/aes.rs` (`MAX_AES_CYCLES_POWER`, `derive_key_cached`)
- Issue #1001; closed classification history #83, #96, #171, #658
