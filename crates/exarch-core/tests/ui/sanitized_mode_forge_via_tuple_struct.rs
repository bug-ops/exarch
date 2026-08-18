//! A `SanitizedMode` must not be assemblable from outside the crate via
//! tuple-struct call syntax. Its single field is private, so
//! `SanitizedMode(todo!())` cannot compile outside `exarch_core` — the only
//! producer of a real `SanitizedMode` is `sanitize_permissions`.

use exarch_core::security::SanitizedMode;

#[allow(unreachable_code)]
fn main() {
    let _mode = SanitizedMode(todo!());
}
