//! A `SecurityConfig<Validated>` must not be forgeable from outside the
//! crate via struct-update syntax, even when starting from a legitimately
//! validated instance. `SecurityConfig`'s fields live behind a private
//! `SecurityConfigFields` member, so struct-literal syntax (with or without
//! `..base`) is rejected outright — there is no public field to name.

fn main() {
    let validated = exarch_core::SecurityConfig::default()
        .validate()
        .unwrap();

    let _forged = exarch_core::SecurityConfig {
        max_compression_ratio: f64::NAN,
        ..validated
    };
}
