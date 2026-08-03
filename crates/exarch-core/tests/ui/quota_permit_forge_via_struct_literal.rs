//! A `QuotaPermit` must not be assemblable from outside the crate via
//! tuple-struct call syntax. Its single field is private, so
//! `QuotaPermit(todo!())` cannot compile outside `exarch_core` — the only
//! producer of a real `QuotaPermit` is `QuotaTracker::reserve`.

use exarch_core::security::QuotaPermit;

#[allow(unreachable_code)]
fn main() {
    let _permit = QuotaPermit(todo!());
}
