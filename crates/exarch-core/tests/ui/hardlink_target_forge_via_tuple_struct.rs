//! A `HardlinkTarget` must not be assemblable from outside the crate via
//! tuple-struct call syntax. Its single field is private, so
//! `HardlinkTarget(..)` cannot compile outside `exarch_core` — the only
//! producer of a real `HardlinkTarget` is `HardlinkTracker` validation.

use exarch_core::security::HardlinkTarget;

fn main() {
    let _target = HardlinkTarget(std::path::PathBuf::from("/etc/passwd"));
}
