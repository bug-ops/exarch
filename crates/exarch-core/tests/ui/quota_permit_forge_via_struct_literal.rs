//! A `QuotaPermit` must not be assemblable from outside the crate via
//! struct-literal syntax. Its `bytes` field is private, so
//! `QuotaPermit { bytes: .. }` cannot compile outside `exarch_core` — the only
//! producer of a real `QuotaPermit` is `QuotaTracker::reserve`.

use exarch_core::security::QuotaPermit;

#[allow(unreachable_code)]
fn main() {
    let _permit = QuotaPermit { bytes: todo!() };
}
