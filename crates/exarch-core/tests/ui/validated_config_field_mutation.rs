//! Regression for the C1 finding on #433/#434/#435: a legitimately obtained
//! `SecurityConfig<Validated>` must not be mutable afterward. If it were,
//! `cfg.max_compression_ratio = f64::NAN` here would reintroduce the exact
//! runtime-invalid-config bug the typestate exists to prevent, since nothing
//! downstream of `ArchiveFormat::extract` re-checks `validate()`'s
//! invariants. `DerefMut` is implemented only for
//! `SecurityConfig<Unvalidated>`, so this must be a compile error.

#[allow(unused_mut)]
fn main() {
    let mut cfg = exarch_core::SecurityConfig::default()
        .validate()
        .unwrap();

    cfg.max_compression_ratio = f64::NAN;
}
