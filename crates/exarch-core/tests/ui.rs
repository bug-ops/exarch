//! Compile-fail regression suite for the sealing guarantees introduced by
//! #433/#434/#435: `SecurityConfig<Validated>` and `ValidatedEntry` must stay
//! non-constructible and non-mutable from outside their invariant-checked
//! construction paths. See `tests/ui/*.rs` for the individual cases.
//!
//! Each fixture ships a committed `.stderr` snapshot that trybuild compares
//! exactly (line/column plus rustc's help text), so this suite also pins
//! *which* sealing mechanism rejects each attempt (private field vs. missing
//! `DerefMut`), not just that compilation failed. A future rustc wording
//! change may require re-blessing the snapshots (delete the stale
//! `.stderr` and re-run to regenerate under `wip/`, then move it back).

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
