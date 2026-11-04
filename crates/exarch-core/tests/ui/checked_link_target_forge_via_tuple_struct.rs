//! A `CheckedLinkTarget` must not be assemblable from outside the crate via
//! tuple-struct call syntax. Its single field is private, so
//! `CheckedLinkTarget(..)` cannot compile outside `exarch_core` — the only
//! producer of a real `CheckedLinkTarget` is a validated `SafeSymlink`.

use exarch_core::CheckedLinkTarget;
use std::path::Path;

fn main() {
    let _target = CheckedLinkTarget(Path::new("/etc/passwd"));
}
