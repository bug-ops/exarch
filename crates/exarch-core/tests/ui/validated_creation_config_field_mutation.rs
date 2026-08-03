//! Regression for #443: a legitimately obtained `CreationConfig<Validated>`
//! must not be mutable afterward. If it were, `cfg.compression_level =
//! Some(200)` here would reintroduce the exact panic the typestate exists to
//! prevent — a forged out-of-range compression level reaching `flate2`'s or
//! `xz2`'s `assert!`/`unwrap()` instead of being rejected by `validate()`.
//! `DerefMut` is implemented only for `CreationConfig<Unvalidated>`, so this
//! must be a compile error.

#[allow(unused_mut)]
fn main() {
    let mut cfg = exarch_core::creation::CreationConfig::new()
        .validate()
        .unwrap();

    cfg.compression_level = Some(200);
}
