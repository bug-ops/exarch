---
aliases:
  - Windows Reserved Device Name Validation
  - SafePath Windows Device Name Rejection
tags:
  - sdd
  - spec
  - security
  - path-validation
  - windows
  - rust
created: 2026-08-03
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
---

# Feature: Windows Reserved Device Name Validation in SafePath

> [!info] Metadata
> **Type**: bug (path-validation robustness gap, Windows-specific)
> **Priority**: P2
> **Subsystem**: exarch-core (`crates/exarch-core/src/types/safe_path.rs`)
> **Origin**: CVE/vulnerability-class monitoring cycle against the tracked
> Reference Project `python/cpython` (tarfile module), per
> `.claude/rules/continuous-improvement.md`. Commit `8b430d6f` (2026-07-02,
> gh-152691) added guidance to `Doc/library/tarfile.rst` that safe
> extraction implementations should check extracted filenames against
> platform-specific semantics, "on Windows some names can have reserved
> meanings." This is a documentation-driven parity finding, not an observed
> exploit or externally reported vulnerability.

## 1. Overview

### Problem Statement

`SafePath::validate` (`crates/exarch-core/src/types/safe_path.rs`) is
exarch-core's central pre-extraction path gate: every archive entry
(TAR/gz/bz2/xz/zst, ZIP, 7z) passes through it before any filesystem write
occurs. It already rejects several explicit classes of unsafe path: path
traversal (`..`), null bytes, unauthorized absolute paths, excessive depth,
and banned path components (`.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`,
`.docker`, `.env`, via `SecurityConfig::banned_path_components` /
`is_path_component_allowed`, config.rs line 754 — case-insensitive exact
match per component).

It has no equivalent check for Windows reserved device names. On Windows,
`CreateFileW` (which `std::fs` calls into for non-`\\?\`-prefixed paths)
maps the classic MS-DOS/Win32 device names — `CON`, `PRN`, `AUX`, `NUL`,
`COM1`-`COM9`, `LPT1`-`LPT9` — to legacy device objects instead of creating
a regular file, both bare (`CON`) and with any trailing extension
(`CON.txt`, `aux.log`, `com1.dat`), case-insensitively. An archive entry
whose base filename matches one of these names can cause extraction of
that entry to fail unpredictably, hang, or interact with a device object
instead of writing ordinary file content — rather than being cleanly
rejected up front like every other unsafe-path class this pipeline already
handles explicitly.

This gap is already self-documented in the codebase. A Windows-only test,
`test_safe_path_windows_reserved_names` (`safe_path.rs` lines 723-736),
iterates the six classic reserved names (`CON`, `PRN`, `AUX`, `NUL`,
`COM1`, `LPT1`) but only asserts the call does not panic; its own comment
states: *"Note: Windows filesystem may reject these, but we don't
explicitly block."* This confirms the gap is known but unaddressed, not
merely theoretical.

This is a correctness/robustness gap in the security validation pipeline,
**not** a directory-traversal or sandbox-escape bypass — it does not allow
writing outside the destination directory. Impact is limited to Windows
extraction targets and requires an archive containing an entry whose base
filename (case-insensitive, with or without extension, at any path depth)
matches a reserved device name. This can occur both from adversarially
crafted archives and from legitimate archives originating from legacy
Windows-authored content.

### Goal

`SafePath::validate` explicitly detects archive entries whose path
components (any depth, not just the final component) case-insensitively
match a Windows reserved device name, with or without a trailing
extension, and rejects them with a typed `ArchiveError` consistent with
how `validate_path` already rejects traversal, null-byte, and
banned-component violations — gated to Windows extraction targets and
configurable via the existing `SecurityConfig` builder pattern. The
existing Windows-only test is updated to assert the actual, now-defined
behavior instead of only "does not panic."

### Out of Scope

- Other Windows filename quirks not related to reserved device names
  (e.g., trailing dot/space stripping, `NTFS` alternate data stream
  syntax `file.txt:stream`) — tracked as a separate `[NEEDS
  CLARIFICATION]` item, not bundled into this fix
- macOS/Unix reserved-name equivalents — none exist; this finding is
  Windows-specific only (see NFR-001)
- Sanitizing/renaming the entry automatically as an alternative to
  rejection — this spec scopes to reject-with-typed-error as the primary
  behavior, with a config opt-out (FR-003), not silent renaming
- Detecting or working around the reserved-name behavior after the fact
  via filesystem error inspection post-write attempt — validation must
  happen in `SafePath::validate`, before any write is attempted
- Auditing `exarch-python` / `exarch-node` bindings directly — per the
  project's Core Security Pipeline architecture, all security logic lives
  exclusively in `exarch-core`; bindings inherit this fix automatically
  through their existing `ArchiveError` conversion layer

## 2. User Stories

### US-001: Windows user extracting an untrusted archive gets a clear rejection

AS A Windows user extracting an archive from an untrusted or unknown source
I WANT an entry named after a reserved device name (e.g., `CON.txt`,
`NUL`, `COM1.log`) to be rejected up front with a clear security error
SO THAT I do not encounter unpredictable extraction failures, hangs, or
unintended interaction with OS device objects partway through an
extraction

**Acceptance criteria:**
```
GIVEN a Windows extraction target and an archive containing an entry named
  "CON.txt" (or any case-insensitive variant of CON, PRN, AUX, NUL,
  COM1-9, LPT1-9, with or without extension)
WHEN extract_archive() (or the CLI/Python/Node.js equivalent) processes
  that entry
THEN SafePath::validate rejects it with a typed ArchiveError before any
  filesystem write is attempted, and the rejection is surfaced consistent
  with how other SecurityViolation errors are reported (skipped entry with
  a warning in partial-extraction mode, or a hard error, per existing
  ExtractionOptions behavior)
```

### US-002: Windows user with legitimate legacy content can opt out

AS A Windows user who needs to extract a legacy archive that legitimately
contains an entry matching a reserved device name (e.g., an old DOS-era
archive)
I WANT an explicit, documented way to allow such entries through
`SecurityConfig`
SO THAT I am not permanently blocked from extracting content I have
consciously chosen to trust, without weakening the default-deny posture
for everyone else

**Acceptance criteria:**
```
GIVEN a SecurityConfig built with the reserved-name check explicitly
  disabled (opt-out, off by default)
WHEN an entry named "CON.txt" is validated
THEN SafePath::validate does not reject it on reserved-name grounds (other
  validation steps still apply unchanged)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a path component (`Component::Normal`, at any depth — not only the final component) case-insensitively matches a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`), with or without a trailing extension, THE SYSTEM SHALL reject the entry with `ArchiveError::SecurityViolation`, consistent with the existing `banned_path_components` rejection path in the same component loop | must |
| FR-002 | WHEN the extraction target platform is not Windows THE SYSTEM SHALL NOT apply reserved-device-name validation, since no equivalent reserved names exist on Unix/macOS filesystems and applying the check there would be a pure behavior regression with no security benefit | must |
| FR-003 | WHEN a `SecurityConfig` is constructed via the builder, callers SHALL be able to explicitly opt out of reserved-device-name rejection (default: enabled/reject), analogous to how `with_banned_path_components` customizes the existing banned-component list | should |
| FR-004 | WHEN validating a path component against the reserved-name set THE SYSTEM SHALL strip only a single trailing extension (text after the last `.`) before comparison, so that `CON.txt` and `CON` both match but `CONTACT.txt` (a superstring, not an exact reserved base name) does not falsely match | must |
| FR-005 | WHEN a reserved-name violation occurs during `list_archive` or `verify_archive` preflight in relaxed mode (`relaxed_for_verify_preflight`, config.rs line 204) THE SYSTEM SHALL surface it as a graceful `VerificationIssue`, matching how other list-level security violations already degrade in that mode, rather than hard-aborting | should |
| FR-006 | THE SYSTEM SHALL update `test_safe_path_windows_reserved_names` (`safe_path.rs` lines 723-736) to assert the defined reject/allow outcome for each case (bare name, name with extension, lowercase variant, intermediate path component, opt-out config) instead of only asserting the call does not panic | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Portability | This validation is Windows-specific by definition (per FR-002); the existing cross-platform test suite (Unix/macOS CI) must show zero behavior change — no new rejections, no new syscalls, no new branches taken on non-Windows builds |
| NFR-002 | Performance | The check must be folded into the existing single-pass `for component in path.components()` loop in `validate_with_context` (safe_path.rs lines 182-224) — the same loop that already performs the `banned_path_components` check — rather than adding a second full-path traversal. It must not add a canonicalize()/syscall to the already-documented "~300-500 ns for non-existing paths" fast path (safe_path.rs lines 64-66) |
| NFR-003 | Consistency | The rejection must use the existing `ArchiveError::SecurityViolation` variant (same as banned-component rejections), not a new error variant — this keeps the error taxonomy stable for downstream consumers (`exarch-cli` formatters, `exarch-python`/`exarch-node` error conversion layers) without requiring changes outside `exarch-core` |
| NFR-004 | Maintainability | Any new public `SecurityConfig` builder method introduced for FR-003 must carry a `///` doc comment with a runnable `# Examples` section, per the workspace's mandatory rustdoc policy (`deny(missing_docs)`-equivalent convention already followed by `with_banned_path_components`) |
| NFR-005 | Testability | Windows-specific test coverage must remain gated behind `#[cfg(windows)]` (as the existing test already is) so it exercises real reserved-name semantics on Windows CI runners without affecting non-Windows test counts or runtime |

## 5. Data Model

Not applicable — this is a validation-logic change to `SafePath::validate`
and, if FR-003 is adopted, one new field/flag on `SecurityConfigFields`. No
new persisted or transmitted entity is introduced.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Entry named exactly `CON` (no extension) | Rejected (`ArchiveError::SecurityViolation`) |
| Entry named `con.txt` (lowercase) | Rejected — comparison is case-insensitive, matching the existing `is_path_component_allowed` precedent |
| Entry named `CONTACT.txt` | Allowed — must not falsely match on names that merely contain a reserved name as a substring/prefix (FR-004) |
| Entry named `COM10.txt` | Allowed — only `COM1`-`COM9` and `LPT1`-`LPT9` are reserved in the classic Win32 semantics; `COM10` is not |
| Reserved name as an intermediate directory component, e.g. `CON/file.txt` | Rejected — validation must check every `Component::Normal`, not only the final one (FR-001) |
| `SecurityConfig` built with the opt-out flag set (FR-003) | Entry allowed through on reserved-name grounds; all other validation steps (traversal, null bytes, depth, other banned components) still apply unchanged |
| Same archive extracted on a non-Windows target | No reserved-name rejection occurs (FR-002); behavior is unchanged from today |
| Reserved-name violation encountered during `list_archive`/`verify_archive` in relaxed preflight mode | Surfaced as a `VerificationIssue` in the report rather than a hard abort (FR-005), matching existing relaxed-mode behavior for other violations |
| Reserved name combined with a path-traversal or null-byte violation in the same entry | Existing validation order in `validate_with_context` (null bytes → absolute path → per-component loop) already runs earlier checks first; the reserved-name check is folded into the same per-component loop as `banned_path_components` and does not need new ordering rules |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `test_safe_path_windows_reserved_names` updated to assert concrete reject/allow outcomes | 100% of the 6 existing names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`, `LPT1`) assert rejection; no remaining "does not panic only" assertions |
| SC-002 | New unit test coverage added | Tests exist for: no-extension match, lowercase-case match, intermediate-path-component match, substring false-positive guard (`CONTACT.txt` allowed), `COM10`/`LPT10` non-match, and opt-out config allowing a reserved name through |
| SC-003 | Non-Windows regression | Full `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node` passes unchanged on non-Windows CI, with no new test failures or skipped counts attributable to this change |
| SC-004 | Hot-path overhead | No new syscall or second path traversal added; validation reuses the existing per-component loop (NFR-002) — confirmed by code review, not a new benchmark (this is not a hot-path-sensitive change per `rust-performance-engineer` triggers) |

## 8. Agent Boundaries

### Always (without asking)
- Fold the reserved-name check into the existing per-component loop in
  `validate_with_context` rather than adding a separate traversal pass
- Use `ArchiveError::SecurityViolation` for the rejection, matching the
  existing banned-component error shape
- Run the full pre-commit check suite (`cargo +nightly fmt --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo nextest run --workspace --all-features --exclude exarch-python
  --exclude exarch-node`, `cargo test --doc --workspace --all-features`,
  the rustdoc gate) before any commit touching `safe_path.rs` or
  `config.rs`
- Update `CHANGELOG.md` under `[Unreleased]`
- Route this through the mandatory `rust-security-maintenance` review
  before merge, since it modifies the security-sensitive path-validation
  pipeline

### Ask First
- Adding a new public `SecurityConfig` builder method for FR-003 (new
  public API surface requires a naming decision and doc-comment
  `# Examples`, consistent with NFR-004)
- Changing the default (reject vs. allow) for the reserved-name check —
  this spec proposes default-reject (consistent with the existing
  non-empty default `banned_path_components` list), but this should be
  confirmed before implementation, not assumed

### Never
- Implement this check in `exarch-cli`, `exarch-python`, or `exarch-node`
  directly — all security logic lives exclusively in `exarch-core` per the
  project's Core Security Pipeline architecture; bindings must inherit the
  fix through the existing `ArchiveError` conversion layer
- Remove or weaken the existing `#[cfg(windows)]` gate on the reserved-name
  test — it must continue to exercise real Windows semantics on Windows CI
- Silently change `test_safe_path_windows_reserved_names`'s scope without
  updating its comment — the current comment documenting the gap must be
  replaced with one documenting the resolved behavior, not left stale

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the default posture be reject-by-default
  (consistent with the existing non-empty `banned_path_components` list
  defaults) or allow-by-default with an opt-in reject flag (consistent
  with most `AllowedFeatures` defaulting to `false`/permissive)? This spec
  assumes reject-by-default per FR-003's phrasing but this should be
  confirmed with the maintainer before implementation.]
- [NEEDS CLARIFICATION: Should the trailing dot/space Windows filename
  quirk (e.g., `CON.`, `CON ` — also documented in Win32 filename rules)
  be bundled into this same fix, or filed as a separate, narrower
  follow-up? It is a related but distinct class of Windows-specific
  filename semantics from the reserved-device-name mapping.]
- [NEEDS CLARIFICATION: Should this check also run on non-Windows hosts as
  a defense-in-depth measure for archives that will later be *moved to* a
  Windows machine (e.g., extracted on Linux CI, then rsynced to a Windows
  fileshare)? FR-002 currently scopes this strictly to `cfg(windows)`
  extraction targets only, matching the project's existing platform-gated
  pattern for `sanitize_permissions` (Unix-only, no inverse check either).]

## 10. See Also

- [[constitution]] — project principles (Core Security Pipeline: all
  security logic lives exclusively in `exarch-core`; validation agents
  section mandates `rust-security-maintenance` review for path-validation
  changes)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — parent security pipeline spec covering
  `SafePath`, `validate_path`, symlink/hardlink validation, and quota
  tracking that this finding extends
- cpython commit [`8b430d6f`](https://github.com/python/cpython/commit/8b430d6f740541f1b9045a89dde43abee2c54bc5)
  (2026-07-02, gh-152691) — added `Doc/library/tarfile.rst` guidance that
  safe extraction should check platform-specific filename semantics,
  citing Windows reserved names as an example; the trigger for this
  finding
- `crates/exarch-core/src/types/safe_path.rs` lines 723-736 — existing
  `#[cfg(windows)] test_safe_path_windows_reserved_names`, currently only
  asserting the call does not panic, with a comment documenting the gap
  this spec closes
- `crates/exarch-core/src/types/safe_path.rs` lines 182-224 — the
  single-pass per-component validation loop where `banned_path_components`
  is currently checked and where the reserved-name check should be folded
  in (FR-001, NFR-002)
- `crates/exarch-core/src/config.rs` lines 207-232 (`SecurityConfigFields`
  defaults, including `banned_path_components`), line 667
  (`with_banned_path_components` builder precedent for FR-003), lines
  748-759 (`is_path_component_allowed` — case-insensitive exact-match
  precedent that FR-004 extends with extension-stripping semantics)
- `.claude/rules/continuous-improvement.md` — Reference Projects section
  tracking `python/cpython tarfile` for CVE/vulnerability-class monitoring;
  CVE & Vulnerability-Class Monitoring section defining the sweep process
  that surfaced this finding
