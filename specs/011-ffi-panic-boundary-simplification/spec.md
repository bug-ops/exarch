---
aliases:
  - FFI Panic Boundary Simplification
  - napi catch_unwind attribute adoption
  - PyO3 defense-in-depth decision
tags:
  - sdd
  - spec
  - research
  - bindings
  - rust
  - ffi
created: 2026-08-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
---

# Feature: FFI Panic Boundary Simplification

> [!info] Metadata
> **Type**: research (architecture / DRY simplification at the FFI panic boundary)
> **Priority**: P3
> **Subsystem**: exarch-node (`crates/exarch-node/src/lib.rs`), exarch-python (`crates/exarch-python/src/lib.rs`)
> **Origin**: PR #412 (merged 2026-08-02) restored panic safety by removing `panic = "abort"` from the release profile and confirming `catch_unwind` guards work across the FFI boundary; this finding is a follow-up architectural review of *how* that guarding is implemented, not a re-litigation of *whether* it's needed

## 1. Overview

### Problem Statement

Both binding crates manually wrap every public entry point in
`std::panic::catch_unwind(std::panic::AssertUnwindSafe(...))`:

- `crates/exarch-node/src/lib.rs` — 8 call sites (lines 184, 257, 316, 375,
  421, 472, 522, 573), plus a shared helper at lines 66-82 that documents the
  `panic = "unwind"` build requirement (issue #395) and defines the
  `catch_unwind(AssertUnwindSafe(f))` wrapper itself.
- `crates/exarch-python/src/lib.rs` — 5 call sites (lines 129, 184, 259, 308,
  360), with the same rationale comment at lines 25-32.

This duplication carries two distinct risks that this spec treats as two
separate, independently addressable gaps:

1. **exarch-node reinvents a first-class framework feature.** napi-rs
   (pinned to `napi` 3.11.0 / `napi-derive` 3.6.0 per `Cargo.lock`) ships a
   declarative `#[napi(catch_unwind)]` attribute that wraps the annotated
   function or method body in `std::panic::catch_unwind` and converts any
   unwinding payload into a `GenericFailure` JS error — precisely the
   behavior exarch-node currently hand-writes at 8 call sites. The manual
   form relies on `AssertUnwindSafe`, which disables the compiler's
   unwind-safety checking per call site; a macro-verified attribute removes
   that manual step and the risk that a future new binding function is added
   without the guard (nothing today forces a new `#[napi]` function to
   remember the wrapper).
2. **exarch-python's manual wrapping duplicates protection PyO3 already
   provides.** PyO3 (pinned to `pyo3` 0.29.0 / `pyo3-macros` 0.29.0) performs
   panic-to-exception conversion automatically at its own C-ABI trampoline
   layer (`pyo3::impl_::trampoline`, referenced from `impl_::pymethods` and
   `impl_::pymodule` in the PyO3 source) for every `#[pyfunction]`,
   `#[pymethods]`, and `#[pymodule]` call — unconditionally, with no
   attribute required. exarch-python's manual `catch_unwind` sits on top of
   that automatic protection. The existing code comment (lib.rs:25, citing
   issue #395) explains why panic-safety is needed at all (the crate must be
   built with `panic = "unwind"`), but does not state whether the manual
   wrapping is intentional belt-and-suspenders or an artifact of assuming
   PyO3 offered no protection of its own.

Neither gap is a currently-observed bug: both crates already catch panics
correctly (confirmed by PR #412). The gap is architectural clarity and DRY —
exarch-node carries avoidable boilerplate that a framework feature already
solves, and exarch-python carries an undocumented redundancy that should be
an explicit decision, not an implicit assumption baked into 5 call sites.

### Goal

Produce an explicit architectural decision, backed by verified evidence, on:
(a) whether exarch-node should adopt `#[napi(catch_unwind)]` in place of its
8 manual `catch_unwind(AssertUnwindSafe(...))` call sites, and (b) whether
exarch-python's manual wrapping is retained as documented defense-in-depth or
removed as redundant with PyO3's automatic trampoline-level protection. This
spec captures the WHAT and WHY; it intentionally does not prescribe the
step-by-step HOW (no plan.md / tasks.md follow-up is requested at this
stage).

### Out of Scope

- Implementation of the attribute migration or comment update (this is a
  specify-only research spec; `/sdd plan` and `/sdd tasks` are explicitly
  not run for this finding)
- Changing `exarch-core`'s panic behavior or public error types
- Revisiting the `panic = "abort"` vs `panic = "unwind"` decision itself
  (settled by issue #395 / PR #412)
- Auditing panic safety in `exarch-cli` (CLI is a single-process binary, not
  an FFI boundary crossing into a host runtime)

## 2. User Stories

### US-001: Maintainer removes node binding boilerplate confidently

AS A maintainer of `exarch-node`
I WANT the public API functions to declare panic safety via
`#[napi(catch_unwind)]` instead of hand-rolled `AssertUnwindSafe` wrappers
SO THAT adding a new binding function cannot silently omit panic-to-error
conversion, and the intent of each function's safety guarantee is visible in
its signature rather than buried in a call-site wrapper

**Acceptance criteria:**
```
GIVEN a new public napi function is added to exarch-node without any
  explicit panic-handling code
WHEN the function is annotated with #[napi(catch_unwind)]
THEN a Rust panic inside the function body is converted to a GenericFailure
  JS error at the call boundary, with no manual AssertUnwindSafe wrapper
  required in the function body
```

### US-002: Maintainer understands why exarch-python double-wraps panics

AS A maintainer of `exarch-python`
I WANT the codebase (comment or spec) to state explicitly whether the manual
`catch_unwind` wrapping is intentional defense-in-depth on top of PyO3's
automatic trampoline-level panic handling, or whether it is redundant and
safe to remove
SO THAT a future contributor does not have to independently re-derive PyO3's
internal panic-handling behavior from source before touching this code, and
does not mistakenly assume the manual wrapper is the *only* protection

**Acceptance criteria:**
```
GIVEN a contributor reads crates/exarch-python/src/lib.rs and sees 5 manual
  catch_unwind call sites
WHEN they consult the code comment or linked architectural decision
THEN they find an explicit statement of whether the manual wrapping is kept
  as intentional defense-in-depth or is scheduled for removal, with the
  PyO3 trampoline behavior cited as the reason the decision was possible
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN. These are requirements on the
*investigation/decision artifact*, not on production code (this is a
research spec).

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN evaluating exarch-node's panic-handling approach THE decision record SHALL document whether `#[napi(catch_unwind)]` (napi 3.11.0 / napi-derive 3.6.0, already present in `Cargo.lock`, no version bump required) is adopted at each of the 8 existing manual call sites, or explicitly rejected with a stated reason | must |
| FR-002 | WHEN evaluating exarch-python's panic-handling approach THE decision record SHALL document whether the 5 manual `catch_unwind` call sites are retained as defense-in-depth or removed as redundant with PyO3's automatic `impl_::trampoline` panic conversion | must |
| FR-003 | IF the decision is to adopt `#[napi(catch_unwind)]` THEN the decision record SHALL note that the shared helper (lib.rs lines 66-82) and its `panic = "unwind"` build-requirement rationale (issue #395) must be preserved or relocated, not silently dropped | must |
| FR-004 | IF the decision is to retain exarch-python's manual wrapping THEN the code comment at lib.rs:25 SHALL be updated (in a follow-up implementation task, not this spec) to state the defense-in-depth rationale explicitly, rather than only explaining the `panic=unwind` build requirement | should |
| FR-005 | WHEN documenting either decision THE decision record SHALL cite the specific napi-rs and PyO3 source/doc references verified during this research (see [[#10. See Also]]) so the claim is independently checkable, not asserted from memory | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | `catch_unwind` (manual or via `#[napi(catch_unwind)]`) only functions correctly when the crate is built with an unwind-capable panic strategy. Both `exarch-node` and `exarch-python` currently rely on `panic = "unwind"` (not `panic = "abort"`), per issue #395 / PR #412. Any future change to the release profile's `panic` setting invalidates this entire panic-safety model for both bindings and must re-trigger this decision |
| NFR-002 | Reliability | Neither manual `catch_unwind` nor `#[napi(catch_unwind)]` catches panics that abort directly — some Rust runtime conditions (e.g. a double panic during unwind, or an explicit `panic = "abort"` build) terminate the process without invoking any unwind-based catch mechanism. This is a hard limit of the approach, not a gap introduced by exarch, and must be stated as a known boundary in the decision record rather than treated as solvable |
| NFR-003 | Correctness / State Consistency | Catching a panic at the FFI boundary provides **no guarantee that external or shared state remains consistent** — it only prevents undefined behavior from unwinding across the FFI boundary; it does not undo partial mutations performed before the panic. This is currently a non-issue because exarch's binding functions call into pure `exarch-core` functions (`extract_archive`, `create_archive`, `list_archive`, `verify_archive`) that take owned/borrowed inputs and return a `Result` without mutating shared state across the boundary. This must be preserved as an explicit invariant: **binding functions must not introduce shared mutable state that a panic could leave inconsistent**, or this NFR is violated and the panic-catching guarantee becomes unsound |
| NFR-004 | Maintainability | Whichever mechanism exarch-node adopts (manual or attribute-based) must scale to new binding functions without requiring a reviewer to manually verify the wrapper is present at each new call site — this is the core DRY motivation for FR-001 |
| NFR-005 | Auditability | The final decision (adopt/reject for each binding) must be traceable to a written record (this spec, and/or a follow-up code comment / ADR) — not left as an implicit choice inferable only from reading diffs |

## 5. Data Model

Not applicable — this is a research/architecture finding about panic-handling
mechanism choice, not a feature introducing new data entities.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A new `#[napi]` function is added to exarch-node after this decision, without `#[napi(catch_unwind)]` | If the decision is "adopt the attribute," this should be caught in code review as a deviation from the established pattern; the spec's FR-001 exists precisely so this has a documented pattern to review against |
| exarch-python's `panic = "unwind"` build requirement is accidentally reverted to `panic = "abort"` (regression of issue #395) | Both bindings' panic-to-error conversion silently stops working (process aborts instead of returning a catchable error) — NFR-001 flags this as the single point of failure for the entire panic-safety model, independent of which catching mechanism is chosen |
| A future `exarch-core` function is changed to mutate shared/static state (e.g., a global cache) and is later called from a binding function that also has a panic-catching guard | NFR-003's invariant would be violated — this scenario is exactly why NFR-003 states the constraint explicitly, so a future contributor evaluates it before adding such core-side state |
| napi-rs or PyO3 changes `#[napi(catch_unwind)]` or the trampoline's panic-conversion behavior in a future major version bump | Re-verify this decision's premises (FR-001/FR-002) against the new version's docs/source before relying on them again; version pins in `Cargo.lock` (napi 3.11.0, napi-derive 3.6.0, pyo3 0.29.0, pyo3-macros 0.29.0) are the baseline this research was verified against |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Explicit decision recorded for exarch-node (adopt `#[napi(catch_unwind)]` or explicitly reject) | 1 decision, documented, citing napi-rs source/docs |
| SC-002 | Explicit decision recorded for exarch-python (retain manual wrapping as defense-in-depth, or remove as redundant) | 1 decision, documented, citing PyO3 trampoline source |
| SC-003 | If exarch-node adopts the attribute, boilerplate call-site count for manual `AssertUnwindSafe` wrapping | 8 sites reduced to 0 (replaced by attribute annotations) |
| SC-004 | If exarch-python retains manual wrapping, the rationale comment reflects a defense-in-depth decision rather than only the `panic=unwind` build note | Comment at lib.rs:25 updated to state the decision (tracked as a follow-up implementation task, not part of this spec's scope) |

## 8. Agent Boundaries

### Always (without asking)
- Cite the specific source location (file path + line, or upstream repo path)
  for any claim about napi-rs or PyO3 internal behavior — no unverified
  assertions about framework internals
- Preserve the `panic = "unwind"` build requirement and its issue #395
  cross-reference in any follow-up code comment, regardless of which
  decision is made

### Ask First
- Removing any of exarch-python's 5 manual `catch_unwind` call sites (this
  is a security-relevant change per the project's `rust-security-maintenance`
  mandatory review policy — even though PyO3 catches panics automatically,
  removing the explicit guard changes the visible safety story of the code
  and should not happen without an explicit maintainer decision)
- Bumping `napi` / `napi-derive` / `pyo3` / `pyo3-macros` versions solely to
  enable this change (current pinned versions already support the relevant
  features per `Cargo.lock`, so no bump should be needed — if one turns out
  to be required, confirm with the maintainer first)

### Never
- Change the release profile's `panic` setting (`unwind` vs `abort`) as a
  side effect of this work — that is the subject of the already-settled
  issue #395 / PR #412, not this finding
- Introduce shared mutable state into binding functions without first
  re-evaluating NFR-003's invariant

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the exarch-node migration to
  `#[napi(catch_unwind)]` and the exarch-python comment update be tracked as
  one combined follow-up issue/PR, or two separate ones, given they are
  independent decisions with independent risk profiles?]
- [NEEDS CLARIFICATION: Does `#[napi(catch_unwind)]` produce a `GenericFailure`
  with an equivalent error message/shape to the current manual wrapper's
  output? Existing consumers (JS callers) may depend on the current error
  shape — this should be verified against napi-rs's `GenericFailure` type
  before any migration PR, not assumed compatible.]

## 10. See Also

- [[constitution]] — project principles (Section I: bindings responsible
  only for type mapping, error conversion, and boundary validation; Section
  V: security-first posture applies to this FFI boundary review)
- [[MOC-specs]] — all specifications
- [[006-python-bindings/spec]] — exarch-python binding spec (PyO3, GIL
  release during I/O)
- [[007-node-bindings/spec]] — exarch-node binding spec (napi-rs, async
  Promises via tokio)
- napi-rs docs: [Error Handling — catch_unwind attribute](https://napi.rs/docs/concepts/error-handling) —
  documents that `#[napi(catch_unwind)]` wraps the function/method in
  `std::panic::catch_unwind` and converts the unwind payload into a
  `GenericFailure`; requires an unwind-capable panic strategy; does not
  catch abort-panics; does not guarantee external state consistency
- PyO3 repository (github.com/PyO3/pyo3): `src/impl_/trampoline.rs`,
  `src/impl_/pymethods.rs`, `src/impl_/pymodule.rs` — all reference
  `catch_unwind` in PyO3's own generated call trampoline, confirming
  automatic panic-to-exception conversion at the C-ABI boundary for every
  `#[pyfunction]` / `#[pymethods]` / `#[pymodule]`
- `crates/exarch-node/src/lib.rs` lines 66-82 (shared helper + issue #395
  rationale), 184, 257, 316, 375, 421, 472, 522, 573 (8 manual call sites)
- `crates/exarch-python/src/lib.rs` lines 25-32 (rationale comment), 129,
  184, 259, 308, 360 (5 manual call sites)
- PR #412 — restored panic safety, removed `panic = "abort"` from release
  profile, confirmed `catch_unwind` works across the FFI boundary
- Issue #395 — original panic-safety requirement that mandated
  `panic = "unwind"` and the manual `catch_unwind` guards in both bindings
