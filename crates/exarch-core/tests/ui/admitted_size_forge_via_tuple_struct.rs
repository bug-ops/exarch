//! An `AdmittedSize` must not be assemblable from outside the crate via
//! tuple-struct call syntax. Its single field is private, so
//! `AdmittedSize(..)` cannot compile outside `exarch_core` — the only producer
//! of a real `AdmittedSize` is the pipeline spending a `QuotaPermit`.

use exarch_core::AdmittedSize;

fn main() {
    let _size = AdmittedSize(u64::MAX);
}
