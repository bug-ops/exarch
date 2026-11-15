---
aliases:
  - CLI Landlock Sandbox
  - Kernel Sandbox for exarch CLI
  - Opt-in Landlock Containment
tags:
  - sdd
  - spec
  - security
  - sandbox
  - landlock
  - cli
  - rust
created: 2026-11-08
updated: 2026-11-15
status: ready
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[005-cli/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
  - "[[024-encrypted-archive-support/spec]]"
---

# Feature: Opt-in Kernel Sandbox (Linux Landlock) for the exarch CLI

> [!info] Metadata
> **Subsystem**: `exarch-cli` (process setup around extract, list and verify). No change to `exarch-core`, `exarch-python`, `exarch-node` or the library API.
> **Issues**: #1025 (implementation), #1231 (the forced-exit test whose seam shares the startup order); batch PR #1230 branch `feat/1230-batch-11-issues`.
> **Decision**: implement (user decision, 2026-11-15), Linux only, opt-in, defense in depth.

> [!abstract]
> All containment in exarch is user-space. A kernel-enforced backstop turns a future logic bug that would write outside the destination into a failed syscall (`EACCES`). The CLI gains `--sandbox best-effort|require` on `extract`, `list` and `verify`: after the archive and destination are prepared and before untrusted parsing, the process restricts itself with Landlock to the archive and the destination subtree. The sandbox never replaces a user-space check and its status is reported honestly.

## 1. Overview

### Problem Statement

`SafePath`, fd-relative `openat` and `mkdirat` with `O_NOFOLLOW`, a mode 0700 staging directory and `QuotaTracker` are sound but have failed before: logic bugs in this layer allowed writes outside the destination, each found after the fact. The process holds the full ambient filesystem authority of the user, so such a bug becomes an escape. Landlock (Linux 5.13+) lets an unprivileged process irreversibly restrict itself; the restriction is per-process, so it fits only the CLI, never the bindings or the library.

No reference archive project (cpython `tarfile`, node-tar, zip2, sevenz-rust2, bsdtar, 7-Zip) ships a kernel sandbox for extraction; the nearest prior art is privilege restriction in security-sensitive parsers (OpenSSH pre-auth child, browser renderers). The value is a defense-in-depth claim, verified by the tests in section 7.

### Goal

When the user opts in on a Linux kernel with Landlock ABI v2 or later, the CLI restricts itself so that it can read only the archive and write only beneath the destination, and on any other platform or kernel it continues (best-effort) and states plainly that no sandbox is active, or fails before touching the archive (`require`).

### Decisions (user, 2026-11-15)

| Topic | Decision |
|-------|----------|
| Platform | Linux only. macOS and Windows sandboxes are non-goals; the code is `cfg(target_os = "linux")` and the dependency sits under `[target.'cfg(target_os = "linux")'.dependencies]` of `exarch-cli` |
| Opt-in | `--sandbox best-effort|require` on `extract`, `list`, `verify`; default off. Env var and config key: none |
| Grants | In-place `extract`: the destination subtree gets every handled filesystem right except EXECUTE and IOCTL_DEV; the archive file gets READ_FILE. `list` and `verify`: the archive file gets READ_FILE only. No READ_DIR anywhere else and nothing on `TMPDIR` |
| Why no READ_DIR | The Linux walk opens directories with `O_PATH`, which Landlock does not mediate, and `realpath` and `lstat` are not mediated either |
| Order | After argument parsing, destination precheck, `password::read` (spec 024) and destination creation; before `interrupt::install` and before any progress thread |
| Threads | Confinement precedes every thread, so later threads inherit the domain; `RestrictSelfFlag::AllThreads` (TSYNC, ABI v8) is requested best-effort as belt and braces |
| ABI floor | v2 (REFER). On v1 the status is `Unavailable(AbiTooOld)` and nothing is restricted |
| Excluded (documented) | `--atomic`, `create`, macOS and Windows, and chmod, chown, xattr and utimens coverage. Each becomes a follow-up issue |

### Out of Scope

- Python and Node bindings and the `exarch-core` API.
- `--atomic` under the sandbox (it needs rename rights on the destination parent); `create` under the sandbox.
- seccomp-bpf and namespaces; making the sandbox default-on.
- Covering chmod, chown, xattr and utimens (Landlock does not mediate them); the docs say so.
- Replacing or weakening any user-space check.

## 2. User Stories

### US-001: Opt in to containment on extract

AS A user extracting an archive from an untrusted source on Linux
I WANT the CLI to confine itself before it parses the archive
SO THAT a logic bug in exarch cannot write outside the destination.

**Acceptance criteria:**
```
GIVEN a Linux kernel with Landlock ABI v2 or later
WHEN I run `exarch extract --sandbox best-effort archive.tar.gz out/`
THEN a benign archive extracts to the same tree as without --sandbox
AND the CLI reports the sandbox as enforced with its ABI level
```

### US-002: Backstop evidence

AS A maintainer
I WANT a test that a write outside the destination fails under the sandbox with a user-space check bypassed by a probe
SO THAT the backstop is shown to work and is not decorative.

**Acceptance criteria:**
```
GIVEN an extraction under --sandbox require
WHEN a probe attempts to create, write, link or rename a path outside the destination
THEN each attempt fails with EACCES and no file exists outside the destination
```

### US-003: Honest behavior where unsupported

AS A user on an older kernel, a non-Linux OS or a container that blocks Landlock
I WANT the CLI to keep working and say no sandbox is active
SO THAT I am never misled about my protection.

**Acceptance criteria:**
```
GIVEN a platform where Landlock is unavailable
WHEN I run extract with --sandbox best-effort
THEN extraction proceeds and the output states that no sandbox is active and why
```

### US-004: Strict mode

AS A pipeline operator
I WANT `--sandbox require` to fail when enforcement is not full
SO THAT a job never runs unsandboxed silently.

**Acceptance criteria:**
```
GIVEN --sandbox require and an unsupported kernel
WHEN I run extract
THEN the CLI exits non-zero before any archive access
```

### US-005: Machine-readable status

AS A script author using `--json`
I WANT the sandbox status in the JSON output
SO THAT tooling can assert protection was in effect.

**Acceptance criteria:**
```
GIVEN --json and --sandbox
WHEN the command completes
THEN the JSON has a `sandbox` key: enforced with ABI, partial with the unhandled set, or unavailable with a reason
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `--sandbox` is given THE CLI SHALL apply a Landlock ruleset to its own process before parsing any archive entry | must |
| FR-002 | THE sandbox SHALL be off by default | must |
| FR-003 | WHEN `extract` runs in place THE ruleset SHALL grant every handled filesystem right except EXECUTE and IOCTL_DEV beneath the destination subtree, and READ_FILE on the archive file | must |
| FR-004 | WHEN `list` or `verify` runs THE ruleset SHALL grant READ_FILE on the archive file only | must |
| FR-005 | THE ruleset SHALL NOT grant READ_DIR outside the destination, nor any access to `TMPDIR`; WHEN a path beyond this set is found to be needed THE implementation SHALL report it as a scope change, never grant it automatically | must |
| FR-006 | Confinement SHALL run in this order in `extract`, `list` and `verify`: argument parsing, destination precheck, `password::read`, destination creation, `sandbox::confine`, `interrupt::install`, the core call. A password source SHALL be consumed before confinement and SHALL never widen the grant | must |
| FR-007 | A missing destination SHALL be created by the CLI before confinement with the same call the core in-place path uses; a test pins that the report and the tree are identical with and without `--sandbox` | must |
| FR-008 | THE CLI SHALL request `RestrictSelfFlag::AllThreads` best-effort and report `all_threads` in the status | should |
| FR-009 | WHEN the kernel ABI is below v2 THE status SHALL be `Unavailable(AbiTooOld)` and nothing SHALL be restricted | must |
| FR-010 | WHEN the kernel lacks Landlock, supports an older ABI than needed, or the platform is not Linux THE CLI SHALL continue under `best-effort` and report exactly what is and is not enforced; under `require` it SHALL exit non-zero before any archive access | must |
| FR-011 | THE CLI SHALL NOT claim sandboxing in any message, log or JSON field unless the kernel reported the ruleset as fully or partially enforced; `Enforced` is reported only on full enforcement | must |
| FR-012 | THE status SHALL be the typed `SandboxStatus { Enforced { abi, all_threads }, Partial { abi, all_threads, unhandled }, Unavailable(Unavailable) }`, never a boolean or string | must |
| FR-013 | `--json` output SHALL carry the status under a `sandbox` key without changing the schema of consumers that ignore it | must |
| FR-014 | WHEN `--sandbox` is combined with `--atomic` or used with `create` THE CLI SHALL refuse the combination with a usage error naming the exclusion | must |
| FR-015 | THE sandbox code and the `landlock` dependency SHALL live only in `exarch-cli`; `exarch-core`, `exarch-python` and `exarch-node` SHALL gain neither | must |
| FR-016 | WHEN the platform is not Linux THE feature SHALL compile out and `--sandbox` SHALL report `Unavailable` (or exit non-zero under `require`) | must |
| FR-017 | THE docs and the CLI skill SHALL state the covered rights (create, write, remove, rename, link, read-file, exec; network from ABI v4, truncate from v3) and that chmod, chown, xattr and utimens are not covered | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The sandbox is defense in depth. It SHALL NOT replace or relax any validation, and its absence SHALL NOT change extraction results |
| NFR-002 | Security | The restriction is applied after handles are opened and before untrusted parsing |
| NFR-003 | Honesty | Reporting never overstates; unknown or partial coverage is `Partial` |
| NFR-004 | Performance | Applying the ruleset is negligible against extraction; throughput with the sandbox on regresses at most 10% |
| NFR-005 | Compatibility | Defined for kernels 5.13 and later; ABI v2 is the floor, negotiation is best-effort above it |
| NFR-006 | Supply chain | `landlock` (0.4.7 at the time of writing) passes `cargo deny`; `unsafe_code` stays denied in the workspace |
| NFR-007 | Testability | CI sets `EXARCH_REQUIRE_LANDLOCK=1` on the Ubuntu test job so that "unavailable" is a test failure; locally the Landlock tests skip when unavailable. If the runner lacks Landlock the work stops and reports back |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SandboxMode` | Requested level | `Off`, `BestEffort`, `Require` |
| `SandboxStatus` | Typed outcome of confinement | `Enforced`, `Partial`, `Unavailable` (see FR-012) |
| Grant set | Rules for one run | operation, archive path, destination subtree |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Kernel without Landlock or LSM disabled | `best-effort` continues, `Unavailable` with reason; `require` exits non-zero before archive access |
| Landlock blocked by a container runtime | Same; the reason names the failing syscall |
| ABI v1 (no REFER) | `Unavailable(AbiTooOld)`, nothing restricted |
| Destination missing | Created before confinement; same report as without `--sandbox` |
| Password file, fd or `/dev/tty` outside the destination | Consumed before confinement; extraction succeeds with the same tree; non-interactive `--password-prompt` fails with the prompt error before confinement, not `EACCES` |
| Hardlink or symlink entries | Created beneath the destination under the same rights; user-space policy decides first |
| 7z or ZIP spool | Falls back as today; nothing granted on `TMPDIR` |
| Progress bars and terminal output | Already-open handles; no path-based reopen |
| A legitimate extraction hits `EACCES` | The error distinguishes a sandbox denial from an ordinary permission failure where detectable |
| `interrupt::install` thread | Spawned after confinement, so it inherits the domain; T4 verifies it does not spawn earlier and moves the spawn if it does |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | A probe writing, creating, linking or renaming outside the destination under `--sandbox require` | fails with `EACCES` in every attempt expressible as a filesystem write |
| SC-002 | Benign extract, list and verify round-trips with the sandbox on | tree and report identical to without the sandbox |
| SC-003 | Reports claiming `Enforced` while the kernel did not enforce | 0 |
| SC-004 | Throughput regression with the sandbox on versus off | at most 10% |
| SC-005 | Unsupported kernel under `best-effort` and `require` | continues and reports unavailable; exits non-zero, each verified by test |
| SC-006 | `extract --sandbox require --password-file <file outside the destination>` on an AES ZIP | succeeds with the same tree as without `--sandbox` |

## 8. Agent Boundaries

### Always (without asking)
- Keep all sandbox code in `exarch-cli`.
- Run `rust-security-maintenance` after any change touching it.
- Update `skills/exarch-cli/SKILL.md` and verify against the running binary for every new flag, output field or exit code.

### Ask First
- Any rule that grants more than the set in FR-003 to FR-005.
- Any change to the `--json` schema beyond the `sandbox` key.

### Never
- Enable the sandbox by default.
- Report sandboxing the kernel did not confirm.
- Relax or remove a user-space validation because a sandbox exists.
- Add sandbox code or dependencies to `exarch-core`, `exarch-python` or `exarch-node`.
- Put worst-case figures or private-advisory detail in public text.

## 9. Open Questions

None open for this scope. Follow-up issues, filed at the end of the batch: `--atomic` under the sandbox; `create` under the sandbox; macOS and Windows sandboxes; chmod, chown, xattr and utimens coverage.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — the user-space pipeline this backs up
- [[005-cli/spec]] — CLI surface hosting the flag
- [[015-atomic-force-destination-swap-hardening/spec]] — atomic swap (excluded here)
- [[024-encrypted-archive-support/spec]] — password sources consumed before confinement
- [[025-cli-landlock-sandbox/plan]] — plan and Contracts
- [Landlock kernel documentation](https://docs.kernel.org/userspace-api/landlock.html) — ABI versions and access rights
- [rust-landlock](https://github.com/landlock-lsm/rust-landlock) — the `landlock` crate
