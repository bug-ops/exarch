//! Regression for #443: the original PoC forged a `CreationConfig` past both
//! `with_compression_level()`'s 1-9 gate and `validate()` via struct-literal
//! syntax (`CreationConfig { compression_level: Some(200), ..Default::default() }`),
//! reaching `flate2`/`xz2` with an out-of-range level and triggering a panic
//! instead of an error. `CreationConfig`'s own `fields` member is private, so
//! `compression_level` is not a field of `CreationConfig` itself (it lives on
//! the wrapped `CreationConfigFields` instead, reachable only through
//! `Deref`/`DerefMut`); the struct-literal syntax is therefore rejected at
//! compile time with E0560, without needing to reach `CreationConfigFields`'s
//! own `#[non_exhaustive]` seal.

fn main() {
    let _forged = exarch_core::creation::CreationConfig {
        compression_level: Some(200),
        ..Default::default()
    };
}
