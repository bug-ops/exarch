//! Compile-fail regression suite for the sealing guarantees introduced by
//! #433/#434/#435: the quota, mode and hardlink-target proofs must stay
//! non-constructible from outside their invariant-checked
//! construction paths. See `tests/ui/*.rs` for the individual cases.
//!
//! Each fixture ships a committed `.stderr` snapshot that trybuild compares
//! exactly (line/column plus rustc's help text), so this suite also pins
//! *which* sealing mechanism rejects each attempt, not just that compilation
//! failed. A future rustc wording change may require re-blessing the
//! snapshots (delete the stale `.stderr` and re-run to regenerate under
//! `wip/`, then move it back).

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}

/// A path whose parent is vetted at write time (`SafePath<Walked>`) must not
/// reach the path-based join. `Walked` is nameable only with the `testing`
/// feature, so this suite is gated on it.
#[cfg(all(feature = "testing", any(unix, target_os = "wasi")))]
#[test]
fn ui_walked_paths() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_testing/*.rs");
}
