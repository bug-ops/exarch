---
aliases:
  - CLI Landlock Sandbox Plan
tags:
  - sdd
  - plan
  - sandbox
created: 2026-11-15
status: ready
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: CLI Landlock Sandbox

> [!info] References
> **Spec**: [[spec]]. Issues #1025, #1231.

## 1. Architecture

### Approach

One module `exarch-cli/src/sandbox.rs`, compiled for Linux only, exposing `confine(SandboxMode, &Grant) -> Result<SandboxStatus, SandboxError>`. The command handlers call it at the fixed point of the spec's FR-006 order. The seam (a stub returning `Unavailable`) is declared early so other tracks can wire to it; the real implementation lands afterwards.

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|-------------------------|
| Crate | `landlock` under `[target.'cfg(target_os = "linux")'.dependencies]` | Maintained, best-effort ABI negotiation, encapsulates the syscalls | Hand-written syscalls (needs `unsafe`) |
| Grant set | Destination subtree: all handled rights except EXECUTE, IOCTL_DEV; archive: READ_FILE; no READ_DIR | The walk uses `O_PATH` (not mediated); `realpath` and `lstat` are not mediated | Broad read on `/` |
| Position | After `password::read` and destination creation, before `interrupt::install` | Threads spawned later inherit the domain; a password source never widens the grant | Confine first |
| TSYNC | Best-effort `AllThreads` | Covers threads that exist before confinement on ABI v8 | Skip |
| ABI floor | v2 | REFER is needed for link and rename inside the destination | v1 |

## 2. Project Structure

```
crates/exarch-cli/
├── src/sandbox.rs            # confine, SandboxMode, SandboxStatus, Grant (Linux); non-Linux stub
├── src/{interrupt,main}.rs   # order; interrupt thread spawn after confinement
├── src/commands/{extract,list,verify}.rs
├── src/output/{json,human}.rs  # `sandbox` key
└── tests/sandbox.rs
```

## 3. Data Model

```rust
pub enum SandboxMode { Off, BestEffort, Require }
pub enum SandboxStatus {
    Enforced { abi: Abi, all_threads: bool },
    Partial { abi: Abi, all_threads: bool, unhandled: UnhandledSet },
    Unavailable(Unavailable), // includes AbiTooOld
}
```

## 4. API Design

CLI only: `--sandbox <best-effort|require>` on `extract`, `list`, `verify`; refused with `--atomic` and absent from `create`. JSON: `"sandbox": { "status": "...", "abi": N, ... }` when the flag is used.

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| Landlock LSM | outbound | `landlock_*` syscalls via the crate | irreversible per process |
| Password sources (spec 024) | inbound | consumed before `confine` | file, fd, tty |

## 6. Security

Defense in depth only; no validation is relaxed. Any extra path found to be needed is a scope change reported to the lead.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|-------------|-----------------|
| Integration | nextest, `tests/sandbox.rs`, Linux | probe writes outside the destination fail with `EACCES`; benign round-trips equal the unsandboxed tree; missing destination equivalence | SC-001, SC-002, FR-007 |
| Status | nextest | `require` on unavailable exits non-zero before archive access; `best-effort` continues; JSON key | SC-003, SC-005 |
| Ordering | nextest, Linux | `--password-file` outside the destination succeeds; non-interactive `--password-prompt` fails before confinement | SC-006 |
| CI | `ci.yml` | `EXARCH_REQUIRE_LANDLOCK=1` on the Ubuntu job | NFR-007 |

## 8. Performance Considerations

Ruleset application is a handful of syscalls; the 10% throughput gate is checked with the sandbox on.

## 9. Rollout Plan

Opt-in flag; CHANGELOG; skill update. Follow-up issues for the documented exclusions.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| Security | Compliant | additive, no check relaxed |
| Simplicity | Compliant | one dependency, Linux only, CLI only |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| CI runner lacks Landlock | med | low | probe job; stop and report if absent |
| `interrupt::install` spawns before confinement | low | med | verify, move the spawn after confinement |

## 12. Contracts

| Item | Preconditions | Postconditions | Undefined behaviour |
|------|---------------|----------------|---------------------|
| `--sandbox best-effort\|require` | Linux; `extract` with in-place staging, or `list` or `verify` | the grant set is exactly the one of FR-003 to FR-005; `Enforced` only if the kernel reported full enforcement; `require` exits non-zero before any archive access when enforcement is not full | combination with `--atomic` and use with `create` are usage errors, not defined behavior |
| `sandbox::confine` | arguments parsed, password read, destination exists | the process (and later threads) cannot access paths outside the grant | non-Linux: returns `Unavailable` |

## See Also

- [[spec]]
- [[MOC-specs]]
