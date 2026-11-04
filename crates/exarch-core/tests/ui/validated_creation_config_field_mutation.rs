//! Regression for #443: a legitimately obtained `CreationConfig<Validated>`
//! must not be mutable afterward. If it were, `cfg.compression_level =
//! ..` here would let a validated config change after the fact, which the
//! typestate exists to prevent.
//! `DerefMut` is implemented only for `CreationConfig<Unvalidated>`, so this
//! must be a compile error.

#[allow(unused_mut)]
fn main() {
    let mut cfg = exarch_core::creation::CreationConfig::new()
        .validate()
        .unwrap();

    cfg.compression_level = Default::default();
}
